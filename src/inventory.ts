import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import {
  InventorySchema,
  ServerSchema,
  validateConnectable,
  type Inventory,
  type Server,
} from "./schema.js";

const DEFAULT_PATH = path.join(homedir(), ".config", "server-inventory", "servers.json");
const DEFAULT_AUDIT_LOG = path.join(homedir(), ".config", "server-inventory", "audit.log");

export function resolveAuditLogPath(): string {
  const fromEnv = process.env.SERVER_INVENTORY_AUDIT_LOG;
  if (fromEnv && fromEnv.trim().length > 0) {
    return fromEnv.startsWith("~")
      ? path.join(homedir(), fromEnv.slice(1))
      : fromEnv;
  }
  return DEFAULT_AUDIT_LOG;
}

// Serializes all read-modify-write cycles against the inventory so concurrent
// MCP tool calls cannot clobber each other.
let writeChain: Promise<unknown> = Promise.resolve();
const TRACE = process.env.SERVER_INVENTORY_TRACE === "1";
let lockSeq = 0;
export function withInventoryLock<T>(fn: () => Promise<T>): Promise<T> {
  const id = ++lockSeq;
  if (TRACE) process.stderr.write(`[inv-lock] #${id} queued\n`);
  const next = writeChain.then(
    async () => {
      if (TRACE) process.stderr.write(`[inv-lock] #${id} start\n`);
      try {
        const result = await fn();
        if (TRACE) process.stderr.write(`[inv-lock] #${id} done ok\n`);
        return result;
      } catch (err) {
        if (TRACE)
          process.stderr.write(
            `[inv-lock] #${id} done err: ${(err as Error).message}\n`,
          );
        throw err;
      }
    },
  );
  writeChain = next.catch(() => undefined);
  return next;
}

export function resolveInventoryPath(): string {
  const fromEnv = process.env.SERVER_INVENTORY_PATH;
  if (fromEnv && fromEnv.trim().length > 0) {
    return fromEnv.startsWith("~")
      ? path.join(homedir(), fromEnv.slice(1))
      : fromEnv;
  }
  return DEFAULT_PATH;
}

async function ensureDir(filePath: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

/** Load the inventory, creating an empty one on first use. */
export async function loadInventory(filePath = resolveInventoryPath()): Promise<Inventory> {
  if (!(await fileExists(filePath))) {
    if (TRACE) process.stderr.write(`[inv-load] ${filePath} missing → creating empty\n`);
    const empty: Inventory = { version: 1, servers: [] };
    await saveInventory(empty, filePath);
    return empty;
  }
  const raw = await fs.readFile(filePath, "utf8");
  if (TRACE)
    process.stderr.write(
      `[inv-load] ${filePath} read ${raw.length} bytes (${(JSON.parse(raw) as { servers?: unknown[] }).servers?.length ?? "?"} servers)\n`,
    );
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Inventory file at ${filePath} is not valid JSON: ${(err as Error).message}`,
    );
  }
  const result = InventorySchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(
      `Inventory file at ${filePath} failed schema validation: ${result.error.message}`,
    );
  }
  return result.data;
}

/** Atomically write the inventory to disk. */
export async function saveInventory(
  inv: Inventory,
  filePath = resolveInventoryPath(),
): Promise<void> {
  if (TRACE)
    process.stderr.write(
      `[inv-save] ${filePath} writing ${inv.servers.length} servers\n`,
    );
  await ensureDir(filePath);
  // sort servers by name for stable diffs
  const sorted: Inventory = {
    version: inv.version,
    servers: [...inv.servers].sort((a, b) => a.name.localeCompare(b.name)),
  };
  const json = JSON.stringify(sorted, null, 2) + "\n";
  const tmp = path.join(
    path.dirname(filePath),
    `.servers.json.${randomBytes(6).toString("hex")}.tmp`,
  );
  await fs.writeFile(tmp, json, { mode: 0o600 });
  await fs.rename(tmp, filePath);
}

function normalizeStringList(values?: string[] | null): string[] {
  if (!values) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    const trimmed = v.trim();
    if (!trimmed) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

/** Normalize a server entry: trim, dedupe lists, drop empty-string fields. */
export function normalizeServer(input: Server): Server {
  const parsed = ServerSchema.parse(input);
  const cleaned: Server = {
    ...parsed,
    name: parsed.name.trim(),
    host: parsed.host?.trim() || null,
    user: parsed.user?.trim() || null,
    port: parsed.port ?? null,
    ssh_alias: parsed.ssh_alias?.trim() || null,
    identity_file: parsed.identity_file?.trim() || null,
    jump_host: parsed.jump_host?.trim() || null,
    description: parsed.description?.trim() || null,
    environment: parsed.environment?.trim() || null,
    role: parsed.role?.trim() || null,
    notes: parsed.notes?.trim() || null,
    groups: normalizeStringList(parsed.groups),
    tags: normalizeStringList(parsed.tags),
  };
  validateConnectable(cleaned);
  return cleaned;
}

export interface ListFilters {
  group?: string;
  tag?: string;
  environment?: string;
  role?: string;
  search?: string;
}

function matchesSearch(s: Server, term: string): boolean {
  const t = term.toLowerCase();
  return [
    s.name,
    s.host,
    s.user,
    s.ssh_alias,
    s.description,
    s.environment,
    s.role,
    s.notes,
    ...s.groups,
    ...s.tags,
  ]
    .filter((v): v is string => typeof v === "string" && v.length > 0)
    .some((v) => v.toLowerCase().includes(t));
}

export function filterServers(servers: Server[], f: ListFilters): Server[] {
  return servers.filter((s) => {
    if (f.group && !s.groups.includes(f.group)) return false;
    if (f.tag && !s.tags.includes(f.tag)) return false;
    if (f.environment && s.environment !== f.environment) return false;
    if (f.role && s.role !== f.role) return false;
    if (f.search && !matchesSearch(s, f.search)) return false;
    return true;
  });
}

/** Build the recommended `ssh` command string for a server. */
export function buildSshCommand(s: Server, extraArgs: string[] = []): string {
  const parts: string[] = ["ssh"];
  if (s.identity_file && !s.ssh_alias) {
    // identity_file via ~/.ssh/config alias is already handled there; only inline when no alias
    parts.push("-i", shellQuote(s.identity_file));
    parts.push("-o", "IdentitiesOnly=yes");
  }
  if (s.port && !s.ssh_alias) {
    parts.push("-p", String(s.port));
  }
  if (s.jump_host && !s.ssh_alias) {
    parts.push("-J", shellQuote(s.jump_host));
  }
  parts.push(...extraArgs.map(shellQuote));
  parts.push(shellQuote(buildSshTarget(s)));
  return parts.join(" ");
}

/** The `[user@]host` (or alias) the agent should pass to `ssh`. */
export function buildSshTarget(s: Server): string {
  if (s.ssh_alias) return s.ssh_alias;
  const host = s.host ?? "";
  return s.user ? `${s.user}@${host}` : host;
}

function shellQuote(v: string): string {
  if (/^[A-Za-z0-9@%+=:,./~_-]+$/.test(v)) return v;
  return `'${v.replace(/'/g, "'\\''")}'`;
}

/** In-memory CRUD over a loaded inventory; caller persists with saveInventory. */
export class InventoryStore {
  constructor(private inv: Inventory) {}

  static async open(filePath = resolveInventoryPath()): Promise<InventoryStore> {
    const inv = await loadInventory(filePath);
    return new InventoryStore(inv);
  }

  snapshot(): Inventory {
    return { version: this.inv.version, servers: [...this.inv.servers] };
  }

  all(): Server[] {
    return [...this.inv.servers];
  }

  list(filters: ListFilters = {}): Server[] {
    return filterServers(this.inv.servers, filters);
  }

  get(name: string): Server | undefined {
    return this.inv.servers.find((s) => s.name === name);
  }

  groups(): { name: string; count: number; members: string[] }[] {
    const map = new Map<string, string[]>();
    for (const s of this.inv.servers) {
      for (const g of s.groups) {
        const arr = map.get(g) ?? [];
        arr.push(s.name);
        map.set(g, arr);
      }
    }
    return [...map.entries()]
      .map(([name, members]) => ({ name, count: members.length, members: members.sort() }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  tags(): { name: string; count: number }[] {
    const map = new Map<string, number>();
    for (const s of this.inv.servers) {
      for (const t of s.tags) {
        map.set(t, (map.get(t) ?? 0) + 1);
      }
    }
    return [...map.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  add(server: Server): Server {
    const normalized = normalizeServer(server);
    if (this.get(normalized.name)) {
      throw new Error(`Server "${normalized.name}" already exists. Use update_server instead.`);
    }
    this.inv.servers.push(normalized);
    return normalized;
  }

  update(name: string, patch: Partial<Server>): Server {
    const existing = this.get(name);
    if (!existing) {
      throw new Error(`Server "${name}" not found.`);
    }
    if (patch.name && patch.name !== name && this.get(patch.name)) {
      throw new Error(`Cannot rename: server "${patch.name}" already exists.`);
    }
    const merged: Server = {
      ...existing,
      ...patch,
      groups: patch.groups !== undefined ? patch.groups : existing.groups,
      tags: patch.tags !== undefined ? patch.tags : existing.tags,
    };
    const normalized = normalizeServer(merged);
    const idx = this.inv.servers.findIndex((s) => s.name === name);
    this.inv.servers[idx] = normalized;
    return normalized;
  }

  remove(name: string): Server {
    const idx = this.inv.servers.findIndex((s) => s.name === name);
    if (idx === -1) throw new Error(`Server "${name}" not found.`);
    const [removed] = this.inv.servers.splice(idx, 1);
    return removed;
  }

  async save(filePath = resolveInventoryPath()): Promise<void> {
    await saveInventory(this.inv, filePath);
  }
}

// Re-exports for convenience
export { ServerSchema };
