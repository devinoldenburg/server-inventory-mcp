/**
 * paths_report builds a single report that tells the agent (and the user)
 * exactly where everything related to this inventory lives on disk:
 *
 *   - the inventory JSON
 *   - the encrypted secrets file + which master-key provider is in use
 *   - the user's SSH config (and which Host blocks each ssh_alias resolves to)
 *   - every referenced identity_file (with absolute path and exists/mode info)
 *   - the audit log (if present)
 *
 * The goal is "show me every file you'd touch on my behalf so I can verify /
 * back up / audit them" — not "show me the secret values".
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { homedir } from "node:os";
import type { Server } from "./schema.js";

export interface PathInfo {
  path: string;
  exists: boolean;
  mode?: string;
  size?: number;
  modified?: string;
  note?: string;
}

export interface IdentityFileReport extends PathInfo {
  /** Servers that reference this identity file. */
  used_by: string[];
  /** Permission warning when the key is world-readable. */
  warning?: string;
}

export interface SshAliasReport {
  alias: string;
  used_by: string[];
  /** Whether the alias is defined in any ~/.ssh/config Host block. */
  defined_in_ssh_config: boolean;
}

export interface PathsReport {
  inventory: PathInfo;
  secrets: PathInfo & { backend: string; master_key: string };
  ssh_config: PathInfo;
  audit_log: PathInfo;
  identity_files: IdentityFileReport[];
  ssh_aliases: SshAliasReport[];
  per_server: Array<{
    name: string;
    ssh_target: string;
    ssh_alias?: string;
    identity_file_resolved?: string;
    secret_keys: string[];
  }>;
}

/** Expand a leading ~/ to the user's home directory. */
export function expandHome(p: string): string {
  if (p.startsWith("~/")) return path.join(homedir(), p.slice(2));
  if (p === "~") return homedir();
  return p;
}

async function statInfo(p: string): Promise<PathInfo> {
  try {
    const s = await fs.stat(p);
    return {
      path: p,
      exists: true,
      mode: "0" + (s.mode & 0o777).toString(8),
      size: s.size,
      modified: s.mtime.toISOString(),
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { path: p, exists: false };
    }
    return {
      path: p,
      exists: false,
      note: `stat error: ${(err as Error).message}`,
    };
  }
}

/** Parse ~/.ssh/config and return the set of Host alias names defined there. */
export async function loadSshConfigHostAliases(): Promise<{
  path: string;
  exists: boolean;
  aliases: Set<string>;
}> {
  const p = path.join(homedir(), ".ssh", "config");
  const aliases = new Set<string>();
  try {
    const raw = await fs.readFile(p, "utf8");
    for (const rawLine of raw.split("\n")) {
      const line = rawLine.replace(/#.*$/, "").trim();
      if (!line) continue;
      const m = line.match(/^Host\s+(.+)$/i);
      if (!m) continue;
      for (const token of m[1].split(/\s+/)) {
        // Skip wildcards — those aren't "named" hosts.
        if (token.includes("*") || token.includes("?")) continue;
        aliases.add(token);
      }
    }
    return { path: p, exists: true, aliases };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { path: p, exists: false, aliases };
    }
    throw err;
  }
}

export interface BuildPathsReportInput {
  servers: Server[];
  inventoryPath: string;
  secretsPath: string;
  secretsBackend: string;
  secretsMasterKey: string;
  auditLogPath: string;
  secretsByServer: Record<string, string[]>;
}

export async function buildPathsReport(
  input: BuildPathsReportInput,
): Promise<PathsReport> {
  const {
    servers,
    inventoryPath,
    secretsPath,
    secretsBackend,
    secretsMasterKey,
    auditLogPath,
    secretsByServer,
  } = input;

  const sshConfig = await loadSshConfigHostAliases();
  const sshConfigInfo: PathInfo = await statInfo(sshConfig.path);

  // identity files: collect unique paths, expand, stat, attach users
  const identityMap = new Map<string, Set<string>>();
  for (const s of servers) {
    if (s.identity_file) {
      const resolved = path.resolve(expandHome(s.identity_file));
      const set = identityMap.get(resolved) ?? new Set<string>();
      set.add(s.name);
      identityMap.set(resolved, set);
    }
  }
  const identityFiles: IdentityFileReport[] = [];
  for (const [resolved, users] of identityMap) {
    const info = await statInfo(resolved);
    const report: IdentityFileReport = {
      ...info,
      used_by: [...users].sort(),
    };
    if (info.exists && info.mode && /[2-7]$/.test(info.mode)) {
      // last octal digit is the "other" bits; >=4 means readable by anyone
      const otherBits = parseInt(info.mode.slice(-1), 8);
      if (otherBits & 0o4) {
        report.warning = "Identity file is world-readable. ssh will refuse to use it. chmod 600 it.";
      }
    }
    identityFiles.push(report);
  }
  identityFiles.sort((a, b) => a.path.localeCompare(b.path));

  // ssh aliases
  const aliasMap = new Map<string, Set<string>>();
  for (const s of servers) {
    if (s.ssh_alias) {
      const set = aliasMap.get(s.ssh_alias) ?? new Set<string>();
      set.add(s.name);
      aliasMap.set(s.ssh_alias, set);
    }
  }
  const sshAliases: SshAliasReport[] = [...aliasMap.entries()]
    .map(([alias, users]) => ({
      alias,
      used_by: [...users].sort(),
      defined_in_ssh_config: sshConfig.aliases.has(alias),
    }))
    .sort((a, b) => a.alias.localeCompare(b.alias));

  const perServer = servers
    .map((s) => ({
      name: s.name,
      ssh_target: s.ssh_alias ? s.ssh_alias : `${s.user ? s.user + "@" : ""}${s.host ?? ""}`,
      ssh_alias: s.ssh_alias ?? undefined,
      identity_file_resolved: s.identity_file
        ? path.resolve(expandHome(s.identity_file))
        : undefined,
      secret_keys: secretsByServer[s.name] ?? [],
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return {
    inventory: await statInfo(inventoryPath),
    secrets: {
      ...(await statInfo(secretsPath)),
      backend: secretsBackend,
      master_key: secretsMasterKey,
    },
    ssh_config: sshConfigInfo,
    audit_log: await statInfo(auditLogPath),
    identity_files: identityFiles,
    ssh_aliases: sshAliases,
    per_server: perServer,
  };
}
