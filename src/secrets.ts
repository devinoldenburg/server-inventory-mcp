/**
 * Encrypted secrets storage for the inventory.
 *
 * On-disk envelope (unencrypted JSON wrapper):
 *   { version: 1, algorithm: "aes-256-gcm", data_version: 2, iv, tag, ciphertext }
 *
 * Inside the ciphertext, the JSON map is:
 *   { server: { key: { value, created_at, updated_at, expires_at? } } }
 *
 * Files without `data_version` (or with data_version: 1) carry the older
 * plain-string shape `{ server: { key: value } }` and are migrated to v2
 * transparently on read. The migrated shape is persisted on the next
 * write — there is no eager migration on load, so a pure-read session
 * leaves the file untouched.
 *
 * Goals:
 *   - Secret values never appear in the public inventory.json on disk.
 *   - On macOS we anchor the master key in the user's login Keychain so the
 *     agent never needs to know a passphrase and the user is prompted at
 *     most once per machine (Always Allow).
 *   - On Linux / Windows / non-keychain hosts, derive the master key from a
 *     passphrase env var (SERVER_INVENTORY_PASSPHRASE) via scrypt.
 *   - All secret values live in a single AES-256-GCM file so we get one
 *     atomic write + tamper detection (auth tag) for the whole store.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { homedir, platform } from "node:os";
import {
  randomBytes,
  scryptSync,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from "node:crypto";

const exec = promisify(execFile);

// ---------- master key providers ----------

export interface MasterKeyProvider {
  /** Return (creating if needed) the 32-byte AES-256-GCM key. */
  getOrCreate(): Promise<Buffer>;
  /** Return the same key if it already exists, else null (no side effects). */
  peek(): Promise<Buffer | null>;
  /** Human-readable location for paths_report. */
  describe(): string;
}

/**
 * Stores a random 32-byte key as a generic password in the macOS login
 * keychain. -A makes it readable without further prompts after the user's
 * one-time "Always Allow" — that's the macOS convention used by every
 * developer-tool credential manager (gh, brew, npm, etc.).
 */
export class MacKeychainMasterKey implements MasterKeyProvider {
  constructor(
    private service = "server-inventory-mcp",
    private account = "master-key",
  ) {}

  async peek(): Promise<Buffer | null> {
    try {
      const { stdout } = await exec("security", [
        "find-generic-password",
        "-s",
        this.service,
        "-a",
        this.account,
        "-w",
      ]);
      return Buffer.from(stdout.trim(), "hex");
    } catch {
      return null;
    }
  }

  async getOrCreate(): Promise<Buffer> {
    const existing = await this.peek();
    if (existing) return existing;
    const key = randomBytes(32);
    await exec("security", [
      "add-generic-password",
      "-s",
      this.service,
      "-a",
      this.account,
      "-w",
      key.toString("hex"),
      "-U",
      "-A",
    ]);
    return key;
  }

  describe(): string {
    return `macOS Keychain (service="${this.service}", account="${this.account}")`;
  }

  async destroy(): Promise<void> {
    try {
      await exec("security", [
        "delete-generic-password",
        "-s",
        this.service,
        "-a",
        this.account,
      ]);
    } catch {
      /* not found is fine */
    }
  }
}

/**
 * Derives a 32-byte key from a passphrase read from an environment variable
 * via scrypt. Same passphrase → same key (deterministic), so the file is
 * portable as long as the env var is set on every machine that reads it.
 */
export class EnvPassphraseMasterKey implements MasterKeyProvider {
  constructor(private envName = "SERVER_INVENTORY_PASSPHRASE") {}

  async peek(): Promise<Buffer | null> {
    const passphrase = process.env[this.envName];
    if (!passphrase) return null;
    return this.derive(passphrase);
  }

  async getOrCreate(): Promise<Buffer> {
    const existing = await this.peek();
    if (existing) return existing;
    throw new Error(
      `Secrets storage requires the ${this.envName} environment variable to be set ` +
        `to a strong passphrase. The MCP server then derives a stable AES key from it.`,
    );
  }

  describe(): string {
    return `env var ${this.envName} (scrypt-derived)`;
  }

  private derive(passphrase: string): Buffer {
    const salt = Buffer.from("server-inventory-mcp:v1:scrypt-salt", "utf8");
    const N = 1 << 15;
    const r = 8;
    const p = 1;
    const maxmem = 64 * 1024 * 1024;
    return scryptSync(passphrase, salt, 32, { N, r, p, maxmem });
  }
}

export function defaultMasterKey(): MasterKeyProvider {
  if (process.env.SERVER_INVENTORY_PASSPHRASE) {
    return new EnvPassphraseMasterKey();
  }
  if (platform() === "darwin") return new MacKeychainMasterKey();
  return new EnvPassphraseMasterKey();
}

// ---------- secrets store: types ----------

export interface SecretsBackendInfo {
  backend: string;
  location: string;
  master_key: string;
  exists: boolean;
  data_version: number;
}

/** One stored secret's metadata, never including the plaintext value. */
export interface SecretMeta {
  key: string;
  created_at: string;
  updated_at: string;
  expires_at?: string;
  expired: boolean;
}

/** Options accepted by set() and updateMeta(). */
export interface SetSecretOptions {
  /**
   * Absolute expiry timestamp as an ISO-8601 string. Pass `null` to clear an
   * existing expiry. Omit (`undefined`) to leave any existing expiry alone.
   */
  expires_at?: string | null;
}

export interface SecretsStore {
  set(
    server: string,
    key: string,
    value: string,
    options?: SetSecretOptions,
  ): Promise<void>;
  get(server: string, key: string): Promise<string | null>;
  getMeta(server: string, key: string): Promise<SecretMeta | null>;
  list(server: string): Promise<string[]>;
  listAll(): Promise<Record<string, string[]>>;
  listMeta(server: string): Promise<SecretMeta[]>;
  listAllMeta(): Promise<Record<string, SecretMeta[]>>;
  delete(server: string, key: string): Promise<boolean>;
  deleteServer(server: string): Promise<number>;
  /**
   * Move every secret from `oldServer` to `newServer` in a single
   * read/decrypt/encrypt/write cycle. Returns the number of keys moved.
   * Throws if `newServer` already has any secrets (no silent merging).
   */
  rename(oldServer: string, newServer: string): Promise<number>;
  describe(): Promise<SecretsBackendInfo>;
}

interface SecretEntry {
  value: string;
  created_at: string;
  updated_at: string;
  expires_at?: string;
}

interface SecretsFileWrapper {
  version: 1;
  algorithm: "aes-256-gcm";
  /** Inner-data shape version. Absent on legacy files (== 1). */
  data_version?: number;
  iv: string;
  tag: string;
  ciphertext: string;
}

const AAD = Buffer.from("server-inventory-mcp:v1", "utf8");

type SecretsMapV1 = Record<string, Record<string, string>>;
type SecretsMapV2 = Record<string, Record<string, SecretEntry>>;

/** Latest inner-data shape version. Bump and add a migration when this changes. */
export const SECRETS_DATA_VERSION = 2;

/**
 * Sequential migrations applied at read time. Each entry takes data shaped
 * for version `key` and returns data shaped for version `key + 1`. To add
 * a future v2→v3 step, append a `2:` entry — readAll walks them in order
 * until it reaches SECRETS_DATA_VERSION.
 */
const SECRETS_MIGRATIONS: Record<
  number,
  (data: unknown, now: string) => unknown
> = {
  1: (raw, now) => {
    const old = (raw ?? {}) as SecretsMapV1;
    const out: SecretsMapV2 = {};
    for (const [server, keys] of Object.entries(old)) {
      if (!keys || typeof keys !== "object") continue;
      out[server] = {};
      for (const [k, v] of Object.entries(keys)) {
        if (typeof v !== "string") continue;
        out[server][k] = { value: v, created_at: now, updated_at: now };
      }
    }
    return out;
  },
};

function migrateSecretsData(
  raw: unknown,
  fromVersion: number,
  toVersion: number,
  now: string,
): unknown {
  let data = raw;
  let v = fromVersion;
  while (v < toVersion) {
    const step = SECRETS_MIGRATIONS[v];
    if (!step) {
      throw new Error(
        `No secrets-data migration from version ${v} to ${v + 1}. ` +
          `Either this client is older than the file, or the file is corrupt.`,
      );
    }
    data = step(data, now);
    v += 1;
  }
  return data;
}

let secretsChain: Promise<unknown> = Promise.resolve();
export function withSecretsLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = secretsChain.then(fn, fn);
  secretsChain = next.catch(() => undefined);
  return next;
}

function isExpired(entry: SecretEntry, nowMs: number): boolean {
  if (!entry.expires_at) return false;
  const t = Date.parse(entry.expires_at);
  if (Number.isNaN(t)) return false;
  return t <= nowMs;
}

function toMeta(key: string, entry: SecretEntry, nowMs: number): SecretMeta {
  const meta: SecretMeta = {
    key,
    created_at: entry.created_at,
    updated_at: entry.updated_at,
    expired: isExpired(entry, nowMs),
  };
  if (entry.expires_at) meta.expires_at = entry.expires_at;
  return meta;
}

export class EncryptedFileSecretsStore implements SecretsStore {
  constructor(
    public readonly filePath: string,
    public readonly masterKey: MasterKeyProvider,
  ) {}

  // ---- low-level encrypted file io ----

  private async readAll(): Promise<SecretsMapV2> {
    let raw: string;
    try {
      raw = await fs.readFile(this.filePath, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
    const wrapper = JSON.parse(raw) as SecretsFileWrapper;
    if (wrapper.version !== 1) {
      throw new Error(
        `Unsupported secrets envelope version: ${wrapper.version}. Expected 1.`,
      );
    }
    if (wrapper.algorithm !== "aes-256-gcm") {
      throw new Error(
        `Unsupported algorithm: ${wrapper.algorithm}. Expected aes-256-gcm.`,
      );
    }
    const dataVersion = wrapper.data_version ?? 1;
    if (dataVersion > SECRETS_DATA_VERSION) {
      throw new Error(
        `Secrets file is data_version ${dataVersion} but this client only understands ` +
          `up to ${SECRETS_DATA_VERSION}. Upgrade server-inventory-mcp.`,
      );
    }
    const key = await this.masterKey.getOrCreate();
    const iv = Buffer.from(wrapper.iv, "hex");
    const tag = Buffer.from(wrapper.tag, "hex");
    const ciphertext = Buffer.from(wrapper.ciphertext, "hex");
    if (iv.length !== 12) throw new Error("Corrupt secrets file: bad IV length.");
    if (tag.length !== 16) throw new Error("Corrupt secrets file: bad tag length.");
    const d = createDecipheriv("aes-256-gcm", key, iv);
    d.setAAD(AAD);
    d.setAuthTag(tag);
    let plain: Buffer;
    try {
      plain = Buffer.concat([d.update(ciphertext), d.final()]);
    } catch {
      throw new Error(
        "Failed to decrypt secrets file. The master key may be wrong (passphrase changed?) or the file may be corrupt.",
      );
    }
    const parsed: unknown = JSON.parse(plain.toString("utf8"));
    if (dataVersion === SECRETS_DATA_VERSION) {
      return (parsed ?? {}) as SecretsMapV2;
    }
    const migrated = migrateSecretsData(
      parsed,
      dataVersion,
      SECRETS_DATA_VERSION,
      new Date().toISOString(),
    );
    return (migrated ?? {}) as SecretsMapV2;
  }

  private async writeAll(map: SecretsMapV2): Promise<void> {
    const key = await this.masterKey.getOrCreate();
    if (key.length !== 32) {
      throw new Error(`Master key must be 32 bytes, got ${key.length}.`);
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(AAD);
    const plaintext = Buffer.from(JSON.stringify(map), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const wrapper: SecretsFileWrapper = {
      version: 1,
      algorithm: "aes-256-gcm",
      data_version: SECRETS_DATA_VERSION,
      iv: iv.toString("hex"),
      tag: tag.toString("hex"),
      ciphertext: ciphertext.toString("hex"),
    };
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    const tmp = path.join(
      path.dirname(this.filePath),
      `.${path.basename(this.filePath)}.${randomBytes(6).toString("hex")}.tmp`,
    );
    await fs.writeFile(tmp, JSON.stringify(wrapper, null, 2) + "\n", { mode: 0o600 });
    await fs.rename(tmp, this.filePath);
  }

  // ---- public API ----

  async set(
    server: string,
    key: string,
    value: string,
    options: SetSecretOptions = {},
  ): Promise<void> {
    assertId(server, "server");
    assertId(key, "key");
    if (typeof value !== "string" || value.length === 0) {
      throw new Error("Secret value must be a non-empty string.");
    }
    if (
      options.expires_at !== undefined &&
      options.expires_at !== null &&
      Number.isNaN(Date.parse(options.expires_at))
    ) {
      throw new Error(
        `expires_at must be an ISO-8601 timestamp or null (got ${JSON.stringify(options.expires_at)}).`,
      );
    }
    const map = await this.readAll();
    const now = new Date().toISOString();
    if (!map[server]) map[server] = {};
    const existing = map[server][key];
    const next: SecretEntry = existing
      ? { ...existing, value, updated_at: now }
      : { value, created_at: now, updated_at: now };
    if (options.expires_at === null) {
      delete next.expires_at;
    } else if (options.expires_at !== undefined) {
      next.expires_at = new Date(options.expires_at).toISOString();
    }
    map[server][key] = next;
    await this.writeAll(map);
  }

  async get(server: string, key: string): Promise<string | null> {
    const map = await this.readAll();
    return map[server]?.[key]?.value ?? null;
  }

  async getMeta(server: string, key: string): Promise<SecretMeta | null> {
    const map = await this.readAll();
    const entry = map[server]?.[key];
    if (!entry) return null;
    return toMeta(key, entry, Date.now());
  }

  async list(server: string): Promise<string[]> {
    const map = await this.readAll();
    return Object.keys(map[server] ?? {}).sort();
  }

  async listAll(): Promise<Record<string, string[]>> {
    const map = await this.readAll();
    const out: Record<string, string[]> = {};
    for (const [s, m] of Object.entries(map)) out[s] = Object.keys(m).sort();
    return out;
  }

  async listMeta(server: string): Promise<SecretMeta[]> {
    const map = await this.readAll();
    const now = Date.now();
    const entries = map[server] ?? {};
    return Object.keys(entries)
      .sort()
      .map((k) => toMeta(k, entries[k], now));
  }

  async listAllMeta(): Promise<Record<string, SecretMeta[]>> {
    const map = await this.readAll();
    const now = Date.now();
    const out: Record<string, SecretMeta[]> = {};
    for (const [s, entries] of Object.entries(map)) {
      out[s] = Object.keys(entries)
        .sort()
        .map((k) => toMeta(k, entries[k], now));
    }
    return out;
  }

  async delete(server: string, key: string): Promise<boolean> {
    const map = await this.readAll();
    if (!map[server] || !(key in map[server])) return false;
    delete map[server][key];
    if (Object.keys(map[server]).length === 0) delete map[server];
    await this.writeAll(map);
    return true;
  }

  async deleteServer(server: string): Promise<number> {
    const map = await this.readAll();
    const n = Object.keys(map[server] ?? {}).length;
    if (n === 0) return 0;
    delete map[server];
    await this.writeAll(map);
    return n;
  }

  async rename(oldServer: string, newServer: string): Promise<number> {
    assertId(oldServer, "oldServer");
    assertId(newServer, "newServer");
    if (oldServer === newServer) return 0;
    const map = await this.readAll();
    const existing = map[oldServer];
    if (!existing || Object.keys(existing).length === 0) return 0;
    if (map[newServer] && Object.keys(map[newServer]).length > 0) {
      throw new Error(
        `Cannot rename secrets ${oldServer} → ${newServer}: ${newServer} already has stored secrets. ` +
          `Delete them first or rename to a different name.`,
      );
    }
    const moved = Object.keys(existing).length;
    map[newServer] = existing;
    delete map[oldServer];
    await this.writeAll(map);
    return moved;
  }

  async describe(): Promise<SecretsBackendInfo> {
    let exists = false;
    let dataVersion = SECRETS_DATA_VERSION;
    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      exists = true;
      try {
        const wrapper = JSON.parse(raw) as SecretsFileWrapper;
        dataVersion = wrapper.data_version ?? 1;
      } catch {
        /* file exists but is unparseable — leave dataVersion at current */
      }
    } catch {
      /* not yet */
    }
    return {
      backend: "encrypted-file (aes-256-gcm)",
      location: this.filePath,
      master_key: this.masterKey.describe(),
      exists,
      data_version: dataVersion,
    };
  }
}

// ---------- defaults ----------

export function resolveSecretsPath(): string {
  const fromEnv = process.env.SERVER_INVENTORY_SECRETS_PATH;
  if (fromEnv && fromEnv.trim().length > 0) {
    return fromEnv.startsWith("~")
      ? path.join(homedir(), fromEnv.slice(1))
      : fromEnv;
  }
  return path.join(homedir(), ".config", "server-inventory", "secrets.enc");
}

let _cached: SecretsStore | null = null;
export function defaultSecretsStore(): SecretsStore {
  if (_cached) return _cached;
  _cached = new EncryptedFileSecretsStore(resolveSecretsPath(), defaultMasterKey());
  return _cached;
}
export function _resetSecretsStoreCacheForTests(): void {
  _cached = null;
}

// ---------- helpers ----------

function assertId(value: string, fieldName: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty string.`);
  }
  if (value.length > 256) {
    throw new Error(`${fieldName} must be 256 characters or fewer.`);
  }
}

/**
 * Parse a relative duration like `30d`, `12h`, `45m`, `2w` into an ISO
 * timestamp `now + duration`. Used by the CLI and MCP tools to accept
 * `--expires-in 30d` style input without forcing the caller to compute the
 * absolute timestamp.
 */
export function parseExpiresIn(input: string, now: Date = new Date()): string {
  const m = /^(\d+)\s*([smhdw])$/.exec(input.trim());
  if (!m) {
    throw new Error(
      `Invalid duration "${input}". Use Ns / Nm / Nh / Nd / Nw (e.g. "30d", "12h").`,
    );
  }
  const n = parseInt(m[1], 10);
  const unit = m[2];
  const seconds =
    unit === "s"
      ? n
      : unit === "m"
        ? n * 60
        : unit === "h"
          ? n * 3600
          : unit === "d"
            ? n * 86400
            : n * 86400 * 7;
  return new Date(now.getTime() + seconds * 1000).toISOString();
}

/**
 * Constant-time string comparison helper exported for tests / future use
 * (e.g. comparing user-supplied secret previews without short-circuiting).
 */
export function safeEquals(a: string, b: string): boolean {
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (aa.length !== bb.length) return false;
  return timingSafeEqual(aa, bb);
}
