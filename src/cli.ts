#!/usr/bin/env node
/**
 * Standalone CLI for the inventory + secrets store.
 *
 * Lets you manage everything without an MCP client. Useful for bootstrapping
 * the inventory from a shell, scripting bulk imports, or quickly inspecting
 * what the agent has been touching.
 *
 *   server-inv ls                    # list servers (alias of list_servers)
 *   server-inv get <name>            # full server detail + ssh command
 *   server-inv groups                # all groups with member names
 *   server-inv targets --group lp    # ssh commands for a group
 *   server-inv add <name> [opts]     # add a new server
 *   server-inv rm <name>             # remove a server (cascades secrets)
 *   server-inv secret set <s> <k>    # store a secret (reads value from stdin)
 *   server-inv secret get <s> <k>    # print one secret value
 *   server-inv secret ls [server]    # list secret keys
 *   server-inv secret rm <s> <k>     # delete a secret
 *   server-inv paths                 # paths_report
 *   server-inv validate              # validate_inventory
 *   server-inv audit [--limit N]     # tail the audit log
 */
import {
  InventoryStore,
  buildSshCommand,
  buildSshTarget,
  resolveAuditLogPath,
  resolveInventoryPath,
} from "./inventory.js";
import {
  defaultSecretsStore,
  parseExpiresIn,
  resolveSecretsPath,
} from "./secrets.js";
import { buildPathsReport, expandHome, loadSshConfigHostAliases } from "./paths.js";
import { audit } from "./audit.js";
import { execEnabled, execOn, sshCheckMany, type SshCheckResult } from "./ssh.js";
import { promises as fs } from "node:fs";
import path from "node:path";
import process from "node:process";

const HELP = `\
server-inv — standalone CLI for server-inventory-mcp

USAGE
  server-inv <command> [args]

INVENTORY
  ls [--group G] [--tag T] [--env E] [--role R] [--search S]
  get <name>
  groups
  tags
  targets (--name N | --group G | --tag T)
  add <name> [--host H] [--user U] [--port P] [--alias A]
             [--key PATH] [--jump JH]
             [--group G ...] [--tag T ...]
             [--env E] [--role R] [--desc TEXT] [--notes TEXT]
  update <name> [--rename-to NEW] [same fields as add]
  rm <name>
  validate
  paths
  info

SECRETS
  secret set <server> <key> [--expires-in DUR | --expires-at ISO]
                                 # value read from stdin (no echo)
                                 # DUR examples: 30d, 12h, 2w
  secret get <server> <key>
  secret ls [server]
  secret rm <server> <key>

SSH
  ssh-check (--name N | --group G | --tag T | --all)
            [--timeout-sec N] [--parallel N] [--hard-timeout-ms N]
            # ssh -o BatchMode=yes <target> true, classified per host
  exec (--name N | --group G | --tag T) [--run] -- <command>
            [--timeout-sec N] [--hard-timeout-ms N] [--parallel N]
            [--max-output-bytes N]
            # Default = dry-run: ssh_check the targets and print the plan,
            # do not execute. Pass --run to actually fire.
            # Requires SERVER_INVENTORY_ALLOW_EXEC=1 either way.

AUDIT
  audit [--limit N]            # default 50

ENVIRONMENT
  SERVER_INVENTORY_PATH         override inventory file location
  SERVER_INVENTORY_SECRETS_PATH override secrets file location
  SERVER_INVENTORY_AUDIT_LOG    override audit log location
  SERVER_INVENTORY_PASSPHRASE   passphrase mode (skip macOS Keychain)
  SERVER_INVENTORY_ALLOW_EXEC   set to 1 to enable \`exec\` / \`exec_on\`
`;

function parseArgs(argv: string[]): {
  positional: string[];
  flags: Record<string, string[]>;
  bool: Set<string>;
} {
  const positional: string[] = [];
  const flags: Record<string, string[]> = {};
  const bool = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      // Bash convention: everything after `--` is positional, no flag
      // parsing. Lets users pass commands with their own --flags to
      // `exec` without them being eaten here.
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        bool.add(key);
      } else {
        (flags[key] ??= []).push(next);
        i++;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags, bool };
}

function f1(flags: Record<string, string[]>, key: string): string | undefined {
  return flags[key]?.[0];
}
function fAll(flags: Record<string, string[]>, key: string): string[] {
  return flags[key] ?? [];
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

function jsonOut(payload: unknown): void {
  process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
}

async function cmdList(args: ReturnType<typeof parseArgs>): Promise<void> {
  const store = await InventoryStore.open();
  const rows = store.list({
    group: f1(args.flags, "group"),
    tag: f1(args.flags, "tag"),
    environment: f1(args.flags, "env") ?? f1(args.flags, "environment"),
    role: f1(args.flags, "role"),
    search: f1(args.flags, "search"),
  });
  jsonOut({
    count: rows.length,
    servers: rows.map((s) => ({
      name: s.name,
      target: buildSshTarget(s),
      groups: s.groups,
      tags: s.tags,
      environment: s.environment,
      role: s.role,
    })),
  });
}

async function cmdGet(name: string): Promise<void> {
  const store = await InventoryStore.open();
  const s = store.get(name);
  if (!s) throw new Error(`Server "${name}" not found.`);
  const secretKeys = await defaultSecretsStore().list(name).catch(() => []);
  jsonOut({
    ...s,
    ssh: { target: buildSshTarget(s), command: buildSshCommand(s) },
    secret_keys: secretKeys,
  });
}

async function cmdGroups(): Promise<void> {
  const store = await InventoryStore.open();
  jsonOut({ groups: store.groups() });
}

async function cmdTags(): Promise<void> {
  const store = await InventoryStore.open();
  jsonOut({ tags: store.tags() });
}

async function cmdTargets(args: ReturnType<typeof parseArgs>): Promise<void> {
  const name = f1(args.flags, "name");
  const group = f1(args.flags, "group");
  const tag = f1(args.flags, "tag");
  const provided = [name, group, tag].filter(Boolean).length;
  if (provided !== 1) {
    throw new Error("Provide exactly one of --name, --group, --tag.");
  }
  const store = await InventoryStore.open();
  let matches;
  if (name) {
    const s = store.get(name);
    if (!s) throw new Error(`Server "${name}" not found.`);
    matches = [s];
  } else if (group) {
    matches = store.list({ group });
  } else {
    matches = store.list({ tag });
  }
  for (const s of matches) {
    process.stdout.write(buildSshCommand(s) + "\n");
  }
}

function buildServerInputFromFlags(
  name: string,
  args: ReturnType<typeof parseArgs>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { name };
  const host = f1(args.flags, "host");
  if (host) out.host = host;
  const user = f1(args.flags, "user");
  if (user) out.user = user;
  const port = f1(args.flags, "port");
  if (port) out.port = parseInt(port, 10);
  const alias = f1(args.flags, "alias");
  if (alias) out.ssh_alias = alias;
  const key = f1(args.flags, "key");
  if (key) out.identity_file = key;
  const jump = f1(args.flags, "jump");
  if (jump) out.jump_host = jump;
  const groups = fAll(args.flags, "group");
  if (groups.length) out.groups = groups;
  const tags = fAll(args.flags, "tag");
  if (tags.length) out.tags = tags;
  const env = f1(args.flags, "env") ?? f1(args.flags, "environment");
  if (env) out.environment = env;
  const role = f1(args.flags, "role");
  if (role) out.role = role;
  const desc = f1(args.flags, "desc") ?? f1(args.flags, "description");
  if (desc) out.description = desc;
  const notes = f1(args.flags, "notes");
  if (notes) out.notes = notes;
  return out;
}

async function cmdAdd(name: string, args: ReturnType<typeof parseArgs>): Promise<void> {
  const store = await InventoryStore.open();
  const added = store.add(buildServerInputFromFlags(name, args) as never);
  await store.save();
  await audit({ tool: "cli:add_server", server: name, ok: true });
  jsonOut({ added });
}

async function cmdUpdate(name: string, args: ReturnType<typeof parseArgs>): Promise<void> {
  const store = await InventoryStore.open();
  const patch = buildServerInputFromFlags(name, args);
  delete (patch as { name?: string }).name;
  const renameTo = f1(args.flags, "rename-to");
  if (renameTo) (patch as { name?: string }).name = renameTo;
  const updated = store.update(name, patch as never);
  await store.save();
  // Migrate secrets on rename — one file rewrite regardless of how many
  // keys the server had.
  if (renameTo && renameTo !== name) {
    await defaultSecretsStore().rename(name, renameTo);
  }
  await audit({ tool: "cli:update_server", server: name, rename_to: renameTo, ok: true });
  jsonOut({ updated });
}

async function cmdRm(name: string): Promise<void> {
  const store = await InventoryStore.open();
  const removed = store.remove(name);
  await store.save();
  const sec = defaultSecretsStore();
  const removedSecrets = await sec.deleteServer(name).catch(() => 0);
  await audit({
    tool: "cli:remove_server",
    server: name,
    ok: true,
    extra: { removed_secret_count: removedSecrets },
  });
  jsonOut({ removed: removed.name, removed_secret_count: removedSecrets });
}

async function cmdValidate(): Promise<void> {
  const store = await InventoryStore.open();
  const all = store.all();
  const sshHosts = (await loadSshConfigHostAliases()).aliases;
  const problems: Array<{ server: string; severity: string; message: string }> = [];
  for (const s of all) {
    if (!s.ssh_alias && !s.host) {
      problems.push({ server: s.name, severity: "error", message: "no ssh_alias or host" });
    }
    if (s.ssh_alias && !sshHosts.has(s.ssh_alias)) {
      problems.push({
        server: s.name,
        severity: "warning",
        message: `ssh_alias "${s.ssh_alias}" not in ~/.ssh/config`,
      });
    }
    if (s.identity_file) {
      const resolved = path.resolve(expandHome(s.identity_file));
      try {
        const st = await fs.stat(resolved);
        if (st.mode & 0o4) {
          problems.push({
            server: s.name,
            severity: "warning",
            message: `${resolved} is world-readable`,
          });
        }
      } catch (err) {
        problems.push({
          server: s.name,
          severity: "error",
          message: `${resolved} not found: ${(err as Error).message}`,
        });
      }
    }
  }
  jsonOut({ checked: all.length, problems, ok: problems.every((p) => p.severity !== "error") });
}

async function cmdPaths(): Promise<void> {
  const store = await InventoryStore.open();
  const sec = defaultSecretsStore();
  const secretsByServer = await sec.listAll().catch(() => ({}));
  const info = await sec.describe();
  const report = await buildPathsReport({
    servers: store.all(),
    inventoryPath: resolveInventoryPath(),
    secretsPath: resolveSecretsPath(),
    secretsBackend: info.backend,
    secretsMasterKey: info.master_key,
    auditLogPath: resolveAuditLogPath(),
    secretsByServer,
  });
  jsonOut(report);
}

async function cmdInfo(): Promise<void> {
  const store = await InventoryStore.open();
  const sec = defaultSecretsStore();
  const all = store.all();
  const sIdx = await sec.listAll().catch(() => ({}));
  jsonOut({
    inventory_path: resolveInventoryPath(),
    secrets_path: resolveSecretsPath(),
    audit_log_path: resolveAuditLogPath(),
    server_count: all.length,
    group_count: store.groups().length,
    tag_count: store.tags().length,
    servers_with_secrets: Object.keys(sIdx).length,
    total_secret_keys: Object.values(sIdx).reduce((n, arr) => n + arr.length, 0),
  });
}

async function cmdSecret(args: ReturnType<typeof parseArgs>): Promise<void> {
  const sub = args.positional[0];
  if (!sub) throw new Error("Usage: secret <set|get|ls|rm>");
  const rest = args.positional.slice(1);
  const sec = defaultSecretsStore();
  switch (sub) {
    case "set": {
      const [server, key] = rest;
      if (!server || !key)
        throw new Error(
          "Usage: secret set <server> <key> [--expires-in DUR | --expires-at ISO]  (value via stdin)",
        );
      const value = await readStdin();
      if (!value)
        throw new Error(
          "Empty value on stdin. Pipe the secret in: echo -n 'pw' | server-inv secret set <s> <k>",
        );
      const expiresAt = f1(args.flags, "expires-at");
      const expiresIn = f1(args.flags, "expires-in");
      let absoluteExpiry: string | null | undefined;
      if (expiresAt !== undefined) {
        absoluteExpiry = expiresAt === "" ? null : expiresAt;
      } else if (expiresIn !== undefined) {
        absoluteExpiry = parseExpiresIn(expiresIn);
      }
      await sec.set(server, key, value, { expires_at: absoluteExpiry });
      const meta = await sec.getMeta(server, key);
      await audit({
        tool: "cli:set_secret",
        server,
        key,
        ok: true,
        extra: meta?.expires_at ? { expires_at: meta.expires_at } : undefined,
      });
      jsonOut({
        server,
        key,
        stored: true,
        value_length: value.length,
        created_at: meta?.created_at,
        updated_at: meta?.updated_at,
        expires_at: meta?.expires_at,
        expired: meta?.expired ?? false,
      });
      return;
    }
    case "get": {
      const [server, key] = rest;
      if (!server || !key) throw new Error("Usage: secret get <server> <key>");
      const v = await sec.get(server, key);
      if (v === null) {
        process.exitCode = 1;
        process.stderr.write(`No secret "${key}" for server "${server}".\n`);
        return;
      }
      process.stdout.write(v + "\n");
      return;
    }
    case "ls": {
      const [server] = rest;
      const wantMeta = args.bool.has("meta");
      if (server) {
        if (wantMeta) {
          jsonOut({ server, entries: await sec.listMeta(server) });
        } else {
          jsonOut({ server, keys: await sec.list(server) });
        }
      } else {
        if (wantMeta) {
          jsonOut({ by_server_meta: await sec.listAllMeta() });
        } else {
          jsonOut({ by_server: await sec.listAll() });
        }
      }
      return;
    }
    case "rm":
    case "delete": {
      const [server, key] = rest;
      if (!server || !key) throw new Error("Usage: secret rm <server> <key>");
      const removed = await sec.delete(server, key);
      await audit({
        tool: "cli:delete_secret",
        server,
        key,
        ok: true,
        extra: { removed },
      });
      jsonOut({ server, key, removed });
      return;
    }
    default:
      throw new Error(`Unknown secret subcommand: ${sub}`);
  }
}

async function cmdSshCheck(args: ReturnType<typeof parseArgs>): Promise<void> {
  const store = await InventoryStore.open();
  const name = f1(args.flags, "name");
  const group = f1(args.flags, "group");
  const tag = f1(args.flags, "tag");
  const all = args.bool.has("all");
  const provided = [name, group, tag, all ? "all" : undefined].filter(Boolean).length;
  if (provided !== 1) {
    throw new Error("Provide exactly one of --name, --group, --tag, --all.");
  }
  let targets;
  if (name) {
    const s = store.get(name);
    if (!s) throw new Error(`Server "${name}" not found.`);
    targets = [s];
  } else if (group) {
    targets = store.list({ group });
  } else if (tag) {
    targets = store.list({ tag });
  } else {
    targets = store.all();
  }
  if (targets.length === 0) {
    jsonOut({ count: 0, results: [], by_outcome: {} });
    return;
  }
  const connectTimeoutSec = numFlag(args, "timeout-sec");
  const hardTimeoutMs = numFlag(args, "hard-timeout-ms");
  const parallel = numFlag(args, "parallel");
  const results = await sshCheckMany(targets, {
    connect_timeout_sec: connectTimeoutSec,
    hard_timeout_ms: hardTimeoutMs,
    parallel,
  });
  const byOutcome: Record<string, number> = {};
  for (const r of results) byOutcome[r.outcome] = (byOutcome[r.outcome] ?? 0) + 1;
  jsonOut({
    count: results.length,
    ok_count: byOutcome.ok ?? 0,
    by_outcome: byOutcome,
    results,
  });
  // Make `ssh-check` script-friendly: non-zero exit if any host wasn't ok.
  if ((byOutcome.ok ?? 0) !== results.length) {
    process.exitCode = 1;
  }
}

async function cmdExec(args: ReturnType<typeof parseArgs>): Promise<void> {
  if (!execEnabled()) {
    throw new Error(
      "exec is disabled. Set SERVER_INVENTORY_ALLOW_EXEC=1 in the environment to enable it.",
    );
  }
  const command = args.positional.join(" ");
  if (!command) throw new Error("Usage: exec (--name N | --group G | --tag T) [--run] <command>");
  const store = await InventoryStore.open();
  const name = f1(args.flags, "name");
  const group = f1(args.flags, "group");
  const tag = f1(args.flags, "tag");
  const provided = [name, group, tag].filter(Boolean).length;
  if (provided !== 1) {
    throw new Error("Provide exactly one of --name, --group, --tag.");
  }
  let targets;
  if (name) {
    const s = store.get(name);
    if (!s) throw new Error(`Server "${name}" not found. Try: server-inv ls`);
    targets = [s];
  } else if (group) {
    targets = store.list({ group });
  } else {
    targets = store.list({ tag });
  }
  if (targets.length === 0) {
    throw new Error("No matching servers. Try: server-inv groups / server-inv tags");
  }

  // Mirror the MCP default: dry-run unless --run is explicitly passed.
  // Keeps human and agent flows on the same rails — same audit footprint,
  // same blast-radius preview, same surprise budget.
  const wantRun = args.bool.has("run");
  if (!wantRun) {
    const probe = await sshCheckMany(targets, {
      connect_timeout_sec: numFlag(args, "timeout-sec"),
      hard_timeout_ms: numFlag(args, "hard-timeout-ms"),
      parallel: numFlag(args, "parallel"),
    });
    const byOutcome: Record<string, number> = {};
    for (const r of probe as SshCheckResult[]) byOutcome[r.outcome] = (byOutcome[r.outcome] ?? 0) + 1;
    const okCount = byOutcome.ok ?? 0;
    await audit({
      tool: "cli:exec_on:dry_run",
      ok: true,
      extra: { target_count: targets.length, ok_count: okCount },
    });
    jsonOut({
      dry_run: true,
      target_count: targets.length,
      would_run: command,
      reachable_count: okCount,
      unreachable_count: targets.length - okCount,
      by_outcome: byOutcome,
      reachability: probe.map((r) => ({
        name: r.name,
        target: r.target,
        outcome: r.outcome,
        message: r.message,
      })),
      next_step:
        okCount === 0
          ? "Zero reachable hosts. Fix connectivity before re-running with --run."
          : `${okCount} of ${targets.length} reachable. Re-run with --run to execute.`,
    });
    if (okCount === 0) process.exitCode = 1;
    return;
  }

  const results = await execOn(targets, command, {
    connect_timeout_sec: numFlag(args, "timeout-sec"),
    hard_timeout_ms: numFlag(args, "hard-timeout-ms"),
    parallel: numFlag(args, "parallel"),
    max_output_bytes: numFlag(args, "max-output-bytes"),
  });
  for (const r of results) {
    await audit({
      tool: "cli:exec_on",
      server: r.name,
      ok: r.ok,
      extra: {
        exit_code: r.exit_code,
        duration_ms: r.duration_ms,
        timed_out: r.timed_out,
      },
    });
  }
  const okCount = results.filter((r) => r.ok).length;
  jsonOut({
    dry_run: false,
    count: results.length,
    ok_count: okCount,
    fail_count: results.length - okCount,
    results,
  });
  if (okCount !== results.length) process.exitCode = 1;
}

function numFlag(args: ReturnType<typeof parseArgs>, key: string): number | undefined {
  const v = f1(args.flags, key);
  if (v === undefined) return undefined;
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) throw new Error(`--${key} must be a number, got "${v}".`);
  return n;
}

async function cmdAudit(args: ReturnType<typeof parseArgs>): Promise<void> {
  const limit = parseInt(f1(args.flags, "limit") ?? "50", 10);
  const filePath = resolveAuditLogPath();
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      jsonOut({ path: filePath, entries: [], note: "no audit log yet" });
      return;
    }
    throw err;
  }
  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const entries = lines.slice(-limit).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return { raw: l };
    }
  });
  jsonOut({ path: filePath, total_lines: lines.length, entries });
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    process.stdout.write(HELP);
    return;
  }

  const args = parseArgs(rest);

  switch (cmd) {
    case "ls":
    case "list":
      return cmdList(args);
    case "get":
      return cmdGet(args.positional[0] ?? throwUsage("get <name>"));
    case "groups":
      return cmdGroups();
    case "tags":
      return cmdTags();
    case "targets":
      return cmdTargets(args);
    case "add":
      return cmdAdd(args.positional[0] ?? throwUsage("add <name> [opts]"), args);
    case "update":
      return cmdUpdate(args.positional[0] ?? throwUsage("update <name> [opts]"), args);
    case "rm":
    case "remove":
      return cmdRm(args.positional[0] ?? throwUsage("rm <name>"));
    case "validate":
      return cmdValidate();
    case "paths":
      return cmdPaths();
    case "info":
      return cmdInfo();
    case "secret":
      return cmdSecret(args);
    case "ssh-check":
    case "check":
      return cmdSshCheck(args);
    case "exec":
      return cmdExec(args);
    case "audit":
      return cmdAudit(args);
    default:
      throw new Error(`Unknown command: ${cmd}\n\n${HELP}`);
  }
}

function throwUsage(usage: string): never {
  throw new Error(`Usage: server-inv ${usage}`);
}

main().catch((err) => {
  process.stderr.write(`server-inv: ${(err as Error).message}\n`);
  process.exit(1);
});
