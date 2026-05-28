#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  InventoryStore,
  buildSshCommand,
  buildSshTarget,
  resolveAuditLogPath,
  resolveInventoryPath,
  withInventoryLock,
} from "./inventory.js";
import {
  defaultSecretsStore,
  parseExpiresIn,
  resolveSecretsPath,
  withSecretsLock,
  type SecretMeta,
} from "./secrets.js";
import {
  buildPathsReport,
  expandHome,
  loadSshConfigHostAliases,
} from "./paths.js";
import { audit } from "./audit.js";
import {
  execEnabled,
  execOn,
  sshCheckMany,
} from "./ssh.js";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Server } from "./schema.js";

const PKG_NAME = "server-inventory-mcp";
const PKG_VERSION = "0.5.0";

const secrets = defaultSecretsStore();

function summary(s: Server, secretKeyCount = 0) {
  return {
    name: s.name,
    target: buildSshTarget(s),
    groups: s.groups,
    tags: s.tags,
    environment: s.environment ?? undefined,
    role: s.role ?? undefined,
    description: s.description ?? undefined,
    secret_count: secretKeyCount,
  };
}

function detail(s: Server, secretKeys: string[] = []) {
  return {
    name: s.name,
    host: s.host ?? undefined,
    user: s.user ?? undefined,
    port: s.port ?? undefined,
    ssh_alias: s.ssh_alias ?? undefined,
    identity_file: s.identity_file ?? undefined,
    jump_host: s.jump_host ?? undefined,
    groups: s.groups,
    tags: s.tags,
    description: s.description ?? undefined,
    environment: s.environment ?? undefined,
    role: s.role ?? undefined,
    notes: s.notes ?? undefined,
    ssh: {
      target: buildSshTarget(s),
      command: buildSshCommand(s),
    },
    secrets: {
      keys: secretKeys,
      hint:
        secretKeys.length > 0
          ? `Call get_secret with this server's name and one of these keys to retrieve a value.`
          : "No secrets stored for this server.",
    },
  };
}

function jsonText(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function errorText(message: string) {
  return {
    isError: true,
    content: [
      {
        type: "text" as const,
        text: message,
      },
    ],
  };
}

async function main() {
  const execStatus = execEnabled()
    ? "ENABLED (SERVER_INVENTORY_ALLOW_EXEC=1)"
    : "DISABLED — set SERVER_INVENTORY_ALLOW_EXEC=1 in this server's environment to enable";
  const server = new McpServer(
    { name: PKG_NAME, version: PKG_VERSION },
    {
      capabilities: { tools: {} },
      instructions: [
        "PURPOSE",
        "  Keeps an inventory of SSH-reachable machines (grouped + tagged), an encrypted",
        "  secret store (passwords, sudo passwords, key passphrases, db creds, API tokens),",
        "  live ssh reachability probes, and opt-in fan-out command execution.",
        "",
        "INTENDED FLOW for 'audit / check / run X on group Y':",
        "  1. list_groups / list_tags     — discover what's defined.",
        "  2. ssh_check { group: \"Y\" }    — confirm hosts are reachable first.",
        "  3. ssh_target_for { group: \"Y\" } — get the exact ssh command per host.",
        "  4. For each host needing a secret: get_secret { server, key } IMMEDIATELY",
        "     before the command that consumes it. Pipe into stdin",
        "     (e.g. `echo \"$pw\" | sudo -S ...`). Never put it on a command line",
        "     (leaks to shell history / `ps`) and never include it in your reply.",
        "  5. exec_on for fan-out execution. Defaults to dry_run:true — read the plan,",
        "     then call again with dry_run:false to actually run.",
        "",
        "AGENTS MAKE MISTAKES. The mistakes this tool has been bitten by, and how to",
        "avoid them:",
        "  - DOUBLE-CREATE: agents retrying mid-stream call add_server twice and get",
        "    'already exists'. If you're modifying an existing host, use update_server.",
        "  - SECRET ECHO: agents narrate what they did and paste the retrieved secret",
        "    into the assistant message. Don't. The audit log records the key name only,",
        "    treat the value the same way. If the user asks 'what's the password',",
        "    answer 'stored — retrieve it with get_secret right before you need it'.",
        "  - SECRET ON COMMAND LINE: building `ssh host \"echo MyP@ss | sudo -S ...\"`",
        "    leaks the secret to shell history and `ps`. Always pipe via stdin from",
        "    your side, never inline the value.",
        "  - delete_secret vs remove_server: delete_secret removes ONE key.",
        "    remove_server removes the inventory entry AND cascades to delete every",
        "    stored secret for it. Read the names carefully.",
        "  - HOMEBREW SSH: agents sometimes build ssh commands from scratch instead of",
        "    using the one ssh_target_for already returned. Trust the output —",
        "    ssh_alias / jump_host / identity_file are handled there.",
        "  - WIDE EXEC WITHOUT PROBE: firing exec_on at a 50-host group with one bad",
        "    DNS entry hangs everything. exec_on defaults to dry_run:true precisely",
        "    so you see reachability before committing.",
        "  - SILENT FAILURE: if a tool result has `isError: true`, treat the operation",
        "    as NOT having happened. Don't proceed as if it had.",
        "  - STALE CACHE: don't reuse list_servers output across mutations. Re-read",
        "    after add_server / update_server / remove_server.",
        "",
        "FILES on this machine:",
        `  Inventory : ${resolveInventoryPath()}`,
        `  Secrets   : ${resolveSecretsPath()} (AES-256-GCM)`,
        `  Audit log : ${resolveAuditLogPath()}`,
        `  exec_on   : ${execStatus}`,
      ].join("\n"),
    },
  );

  // ---------- list_servers ----------
  server.registerTool(
    "list_servers",
    {
      title: "List servers",
      description:
        "List servers in the inventory. Optional filters: group (e.g. 'logicplanes'), tag, environment, role, or a free-text search across name/host/description/tags. Returns a compact summary; use get_server for full details.",
      inputSchema: {
        group: z.string().optional().describe("Only servers in this group"),
        tag: z.string().optional().describe("Only servers with this tag"),
        environment: z.string().optional().describe("Only servers with this environment (e.g. 'production')"),
        role: z.string().optional().describe("Only servers with this role (e.g. 'web', 'db')"),
        search: z.string().optional().describe("Free-text match across name/host/description/tags/groups"),
      },
    },
    async (args) =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        const matched = store.list(args);
        const secretIndex: Record<string, string[]> = await withSecretsLock(() =>
          secrets.listAll().catch(() => ({}) as Record<string, string[]>),
        );
        const rows = matched.map((s) => summary(s, secretIndex[s.name]?.length ?? 0));
        return jsonText({ count: rows.length, servers: rows });
      }),
  );

  // ---------- get_server ----------
  server.registerTool(
    "get_server",
    {
      title: "Get server details",
      description:
        "Get the full inventory entry for a single server by its unique name, including the ssh target and a ready-to-run ssh command.",
      inputSchema: {
        name: z.string().describe("The server name (unique key in the inventory)"),
      },
    },
    async ({ name }) =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        const s = store.get(name);
        if (!s) {
          return errorText(
            `Server "${name}" not found. Call list_servers to see what's defined, ` +
              `or add_server if "${name}" is a new entry.`,
          );
        }
        const secretKeys = await secrets.list(name).catch(() => []);
        return jsonText(detail(s, secretKeys));
      }),
  );

  // ---------- list_groups ----------
  server.registerTool(
    "list_groups",
    {
      title: "List groups",
      description:
        "List every distinct group across the inventory with member counts and member names. Use this to discover groups like 'logicplanes' before listing the servers in them.",
      inputSchema: {},
    },
    async () =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        return jsonText({ groups: store.groups() });
      }),
  );

  // ---------- list_tags ----------
  server.registerTool(
    "list_tags",
    {
      title: "List tags",
      description: "List every distinct tag across the inventory with usage counts.",
      inputSchema: {},
    },
    async () =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        return jsonText({ tags: store.tags() });
      }),
  );

  // ---------- ssh_target_for ----------
  server.registerTool(
    "ssh_target_for",
    {
      title: "Resolve ssh targets",
      description:
        "Resolve one or more servers to ssh connection info. Pass exactly one of: name (single server), group (every server in that group), or tag. Returns the ssh target (alias or user@host) and a ready-to-run ssh command for each match — feed these to the agent's ssh tool to connect.\n\nMistakes to avoid:\n  - Use the returned `command` string verbatim. Don't rebuild it from `host` / `user` / `port` — ssh_alias / jump_host / identity_file are handled in the returned command, and you'll drop them if you reconstruct.\n  - This does NOT probe reachability. If you need to know whether the host is up before connecting, use ssh_check.",
      inputSchema: {
        name: z.string().optional(),
        group: z.string().optional(),
        tag: z.string().optional(),
      },
    },
    async ({ name, group, tag }) =>
      withInventoryLock(async () => {
        const provided = [name, group, tag].filter(Boolean).length;
        if (provided !== 1) {
          return errorText(
            "Provide exactly one of: name, group, tag. " +
              "(list_groups / list_tags / list_servers are the tools to discover what's defined.)",
          );
        }
        const store = await InventoryStore.open();
        let matches: Server[];
        if (name) {
          const s = store.get(name);
          if (!s) {
            return errorText(
              `Server "${name}" not found. Call list_servers to see what's defined.`,
            );
          }
          matches = [s];
        } else if (group) {
          matches = store.list({ group });
          if (matches.length === 0) {
            return errorText(
              `No servers in group "${group}". Call list_groups to see what's defined.`,
            );
          }
        } else {
          matches = store.list({ tag: tag! });
          if (matches.length === 0) {
            return errorText(
              `No servers with tag "${tag}". Call list_tags to see what's defined.`,
            );
          }
        }
        return jsonText({
          count: matches.length,
          targets: matches.map((s) => ({
            name: s.name,
            target: buildSshTarget(s),
            command: buildSshCommand(s),
            ssh_alias: s.ssh_alias ?? undefined,
            host: s.host ?? undefined,
            user: s.user ?? undefined,
            port: s.port ?? undefined,
            identity_file: s.identity_file ?? undefined,
            jump_host: s.jump_host ?? undefined,
          })),
        });
      }),
  );

  // ---------- add_server ----------
  server.registerTool(
    "add_server",
    {
      title: "Add a server",
      description:
        "Add a NEW server to the inventory. Either ssh_alias (a host alias from ~/.ssh/config) or host must be provided. Names must be unique.\n\nMistakes to avoid:\n  - If you're modifying an existing server, this is the wrong tool — use update_server. add_server errors with 'already exists' on collision; do not catch that and retry.\n  - On retry after a network blip, call list_servers first to see whether the previous call already landed.\n  - Do NOT pass empty strings for fields you don't have — omit them.",
      inputSchema: {
        name: z.string().describe("Unique server name (letters, digits, dot, underscore, dash)"),
        host: z.string().optional(),
        user: z.string().optional(),
        port: z.number().int().positive().max(65535).optional(),
        ssh_alias: z.string().optional().describe("Preferred — alias defined in ~/.ssh/config"),
        identity_file: z.string().optional().describe("Absolute path or ~/ path to private key"),
        jump_host: z.string().optional().describe("Optional [user@]host[:port] jump host (-J)"),
        groups: z.array(z.string()).optional(),
        tags: z.array(z.string()).optional(),
        description: z.string().optional(),
        environment: z.string().optional(),
        role: z.string().optional(),
        notes: z.string().optional(),
      },
    },
    async (args) =>
      withInventoryLock(async () => {
        try {
          const store = await InventoryStore.open();
          const created = store.add({
            ...args,
            groups: args.groups ?? [],
            tags: args.tags ?? [],
          } as Server);
          await store.save();
          const secretKeys = await secrets.list(created.name).catch(() => []);
          await audit({ tool: "add_server", server: created.name, ok: true });
          return jsonText({ added: detail(created, secretKeys) });
        } catch (err) {
          await audit({
            tool: "add_server",
            server: args.name,
            ok: false,
            error: (err as Error).message,
          });
          throw err;
        }
      }),
  );

  // ---------- update_server ----------
  server.registerTool(
    "update_server",
    {
      title: "Update a server",
      description:
        "Update fields on an EXISTING server. Only the fields you pass are changed. To clear a field, pass an empty string. To rename, set rename_to (secrets are migrated in a single atomic write).\n\nMistakes to avoid:\n  - This is the right tool for 'change something about a server I already added'. If you instead use add_server you'll get 'already exists' and the change won't land.\n  - Renaming to an existing name fails — call list_servers first if you're not sure.\n  - Passing rename_to that matches the current name is a no-op, not an error.",
      inputSchema: {
        name: z.string().describe("Existing server name"),
        rename_to: z.string().optional(),
        host: z.string().optional(),
        user: z.string().optional(),
        port: z.number().int().positive().max(65535).optional(),
        ssh_alias: z.string().optional(),
        identity_file: z.string().optional(),
        jump_host: z.string().optional(),
        groups: z.array(z.string()).optional(),
        tags: z.array(z.string()).optional(),
        description: z.string().optional(),
        environment: z.string().optional(),
        role: z.string().optional(),
        notes: z.string().optional(),
      },
    },
    async (args) =>
      withInventoryLock(async () => {
        const { name, rename_to, ...rest } = args;
        try {
          const store = await InventoryStore.open();
          const patch: Partial<Server> = { ...rest };
          if (rename_to !== undefined) patch.name = rename_to;
          const updated = store.update(name, patch);
          await store.save();
          // If renamed, migrate any associated secrets to the new name so
          // they don't orphan. Single read/encrypt/write cycle regardless
          // of how many keys are stored.
          if (rename_to && rename_to !== name) {
            await withSecretsLock(() => secrets.rename(name, rename_to));
          }
          const secretKeys = await secrets.list(updated.name).catch(() => []);
          await audit({
            tool: "update_server",
            server: name,
            rename_to: rename_to,
            ok: true,
          });
          return jsonText({ updated: detail(updated, secretKeys) });
        } catch (err) {
          await audit({
            tool: "update_server",
            server: name,
            rename_to: rename_to,
            ok: false,
            error: (err as Error).message,
          });
          throw err;
        }
      }),
  );

  // ---------- remove_server ----------
  server.registerTool(
    "remove_server",
    {
      title: "Remove a server",
      description:
        "Delete a server from the inventory by name. DESTRUCTIVE: cascades to drop every secret stored for this server.\n\nMistakes to avoid:\n  - Confusing this with delete_secret. delete_secret removes ONE key from ONE server. remove_server removes the entire inventory entry AND every secret stored under that name.\n  - Calling this 'just to clean up' on a server you might still need. There is no undo — the encrypted secrets are gone after the next file write.\n  - Use update_server if you want to rename, change tags, or otherwise modify — not remove + add.",
      inputSchema: {
        name: z.string(),
      },
    },
    async ({ name }) =>
      withInventoryLock(async () => {
        try {
          const store = await InventoryStore.open();
          const removed = store.remove(name);
          await store.save();
          // Cascade: drop any secrets associated with this server.
          const removedSecrets = await withSecretsLock(() =>
            secrets.deleteServer(name).catch(() => 0),
          );
          await audit({
            tool: "remove_server",
            server: name,
            ok: true,
            extra: { removed_secret_count: removedSecrets },
          });
          return jsonText({
            removed: removed.name,
            removed_secret_count: removedSecrets,
          });
        } catch (err) {
          await audit({
            tool: "remove_server",
            server: name,
            ok: false,
            error: (err as Error).message,
          });
          throw err;
        }
      }),
  );

  // ---------- inventory_info ----------
  server.registerTool(
    "inventory_info",
    {
      title: "Inventory info",
      description:
        "Where the inventory file lives, total server count, group count, tag count. Useful for debugging which inventory the agent is reading.",
      inputSchema: {},
    },
    async () =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        const all = store.all();
        const secretIndex: Record<string, string[]> = await withSecretsLock(() =>
          secrets.listAll().catch(() => ({}) as Record<string, string[]>),
        );
        return jsonText({
          inventory_path: resolveInventoryPath(),
          secrets_path: resolveSecretsPath(),
          server_count: all.length,
          group_count: store.groups().length,
          tag_count: store.tags().length,
          servers_with_secrets: Object.keys(secretIndex).length,
          total_secret_keys: Object.values(secretIndex).reduce(
            (n, arr) => n + arr.length,
            0,
          ),
        });
      }),
  );

  // ---------- paths_report ----------
  server.registerTool(
    "paths_report",
    {
      title: "Where every file lives",
      description:
        "One-shot report of every file path this server cares about: the inventory JSON, the encrypted secrets file (with backend + master-key provider), ~/.ssh/config, the audit log, every identity_file referenced by the inventory (with stat info and a chmod warning if any are world-readable), every ssh_alias used (with whether it actually resolves in ~/.ssh/config), and a per-server breakdown that ties names → ssh target → resolved key path → secret keys. Use this before any operation that needs to find keys / passwords / users on disk.",
      inputSchema: {},
    },
    async () => {
      const [invSnap, secretsByServer, secretsInfo] = await Promise.all([
        withInventoryLock(async () => {
          const s = await InventoryStore.open();
          return s.all();
        }),
        withSecretsLock(() =>
          defaultSecretsStore().listAll().catch(() => ({}) as Record<string, string[]>),
        ),
        defaultSecretsStore().describe(),
      ]);
      const report = await buildPathsReport({
        servers: invSnap,
        inventoryPath: resolveInventoryPath(),
        secretsPath: resolveSecretsPath(),
        secretsBackend: secretsInfo.backend,
        secretsMasterKey: secretsInfo.master_key,
        auditLogPath: resolveAuditLogPath(),
        secretsByServer,
      });
      return jsonText(report);
    },
  );

  // ---------- validate_inventory ----------
  server.registerTool(
    "validate_inventory",
    {
      title: "Sanity-check every server",
      description:
        "Validate every server in the inventory: that referenced identity_file paths exist on disk and aren't world-readable, that ssh_aliases are defined in ~/.ssh/config, and that each entry is reachable in principle (has ssh_alias OR host). Returns { problems: [{ server, severity, message }] }; empty array means everything checks out.",
      inputSchema: {},
    },
    async () =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        const all = store.all();
        const sshConfigHosts = (await loadSshConfigHostAliases()).aliases;
        const inventoryNames = new Set(all.map((s) => s.name));
        const secretsMeta: Record<string, SecretMeta[]> = await withSecretsLock(() =>
          secrets.listAllMeta().catch(() => ({}) as Record<string, SecretMeta[]>),
        );
        const problems: Array<{
          server: string;
          severity: "error" | "warning";
          message: string;
        }> = [];
        // Surface orphan secret rows (server not in inventory) and expired entries.
        for (const [srvName, entries] of Object.entries(secretsMeta)) {
          if (!inventoryNames.has(srvName)) {
            problems.push({
              server: srvName,
              severity: "warning",
              message: `Orphan secrets: server "${srvName}" is in the secrets store but not in the inventory. ${entries.length} key(s).`,
            });
          }
          for (const e of entries) {
            if (e.expired) {
              problems.push({
                server: srvName,
                severity: "warning",
                message: `Secret "${e.key}" expired at ${e.expires_at}. Rotate it.`,
              });
            }
          }
        }
        for (const s of all) {
          if (!s.ssh_alias && !s.host) {
            problems.push({
              server: s.name,
              severity: "error",
              message: "No ssh_alias and no host — unreachable.",
            });
          }
          if (s.ssh_alias && !sshConfigHosts.has(s.ssh_alias)) {
            problems.push({
              server: s.name,
              severity: "warning",
              message: `ssh_alias "${s.ssh_alias}" is not defined in ~/.ssh/config; ssh will fall back to using it as a hostname.`,
            });
          }
          if (s.identity_file) {
            const resolved = path.resolve(expandHome(s.identity_file));
            try {
              const st = await fs.stat(resolved);
              const otherBits = st.mode & 0o7;
              if (otherBits & 0o4) {
                problems.push({
                  server: s.name,
                  severity: "warning",
                  message: `identity_file ${resolved} is world-readable; ssh will refuse to use it. chmod 600.`,
                });
              }
            } catch (err) {
              problems.push({
                server: s.name,
                severity: "error",
                message: `identity_file ${resolved} not found: ${(err as Error).message}`,
              });
            }
          }
        }
        return jsonText({
          checked: all.length,
          problems,
          ok: problems.filter((p) => p.severity === "error").length === 0,
        });
      }),
  );

  // ---------- secrets_info ----------
  server.registerTool(
    "secrets_info",
    {
      title: "Secrets backend info",
      description:
        "Where secrets are stored, which encryption backend is in use, and which master-key provider (macOS Keychain or env passphrase). Does NOT reveal any secret values.",
      inputSchema: {},
    },
    async () => {
      const info = await secrets.describe();
      return jsonText(info);
    },
  );

  // ---------- set_secret ----------
  server.registerTool(
    "set_secret",
    {
      title: "Store a secret for a server",
      description:
        "Encrypt and store a secret value (password, sudo password, API token, key passphrase, ...) for a server. Common keys: password, sudo_password, ssh_passphrase, db_password, api_token. The value is encrypted with AES-256-GCM at rest and never written to the inventory file. Optionally set an expiry: pass expires_at (ISO timestamp) OR expires_in (duration like '30d', '12h', '90d') so a future validate_inventory call can flag stale credentials. Updating an existing key preserves its created_at; updated_at is bumped on every write. Returns the metadata that was just stored, never the value.\n\nMistakes to avoid:\n  - Setting the same (server, key) twice REPLACES the previous value with no warning. The old value is gone. Confirm before overwriting.\n  - Do not include the secret value in your reply to the user, in the audit log via 'extra', or in any other tool argument.\n  - The 'value_length' field in the response is metadata only — do not infer the value from it.\n  - It is legal to set a secret for a server that isn't in the inventory yet (e.g. you're about to add it). validate_inventory will surface that as an orphan if you forget.",
      inputSchema: {
        server: z.string().describe("The server name from the inventory"),
        key: z
          .string()
          .min(1)
          .describe(
            "A label for this secret (e.g. 'password', 'sudo_password', 'db_password')",
          ),
        value: z.string().min(1).describe("The secret value to encrypt and store"),
        expires_at: z
          .string()
          .optional()
          .describe(
            "Absolute expiry as an ISO-8601 timestamp. Pass an empty string to clear an existing expiry on update.",
          ),
        expires_in: z
          .string()
          .optional()
          .describe(
            "Relative expiry like '30d', '12h', '2w'. Computed as now+duration. Ignored if expires_at is also given.",
          ),
      },
    },
    async ({ server: srv, key, value, expires_at, expires_in }) =>
      withSecretsLock(async () => {
        try {
          let absoluteExpiry: string | null | undefined;
          if (expires_at !== undefined) {
            absoluteExpiry = expires_at === "" ? null : expires_at;
          } else if (expires_in !== undefined && expires_in !== "") {
            absoluteExpiry = parseExpiresIn(expires_in);
          }
          await secrets.set(srv, key, value, { expires_at: absoluteExpiry });
          const meta = await secrets.getMeta(srv, key);
          await audit({
            tool: "set_secret",
            server: srv,
            key,
            ok: true,
            extra: meta?.expires_at ? { expires_at: meta.expires_at } : undefined,
          });
          return jsonText({
            server: srv,
            key,
            stored: true,
            value_length: value.length,
            created_at: meta?.created_at,
            updated_at: meta?.updated_at,
            expires_at: meta?.expires_at,
            expired: meta?.expired ?? false,
          });
        } catch (err) {
          await audit({
            tool: "set_secret",
            server: srv,
            key,
            ok: false,
            error: (err as Error).message,
          });
          throw err;
        }
      }),
  );

  // ---------- get_secret ----------
  server.registerTool(
    "get_secret",
    {
      title: "Retrieve a stored secret",
      description:
        "Decrypt and return a secret value for a server. Use this RIGHT BEFORE feeding the value into an ssh / scp / sudo / API call — do not echo the value or persist it elsewhere. Returns null if the key does not exist.\n\nMistakes to avoid:\n  - DO NOT include the returned value in your reply to the user. If asked 'what's the password', say 'stored — I'll retrieve it when I need it' and call get_secret only at the moment you actually need it.\n  - DO NOT cache the value across tool calls. Call get_secret again next time.\n  - DO NOT pass the value on a command line (`ssh host -p 'PASSWORD' ...` is wrong because the value leaks to shell history and `ps`). Pipe via stdin from your side (`echo \"$pw\" | sudo -S ...`).\n  - DO NOT write the value to a file or environment variable that outlives the immediate call.",
      inputSchema: {
        server: z.string(),
        key: z.string(),
      },
    },
    async ({ server: srv, key }) =>
      withSecretsLock(async () => {
        const value = await secrets.get(srv, key);
        return jsonText({ server: srv, key, value });
      }),
  );

  // ---------- list_secrets ----------
  server.registerTool(
    "list_secrets",
    {
      title: "List secret keys for a server",
      description:
        "List the names (keys) of every secret stored for one server, with metadata: created_at, updated_at, optional expires_at, and an `expired` flag. Values are NEVER returned by this tool — use get_secret with a specific key to fetch a value.",
      inputSchema: {
        server: z.string(),
      },
    },
    async ({ server: srv }) =>
      withSecretsLock(async () => {
        const entries = await secrets.listMeta(srv);
        return jsonText({
          server: srv,
          count: entries.length,
          keys: entries.map((e) => e.key),
          entries,
          expired_count: entries.filter((e) => e.expired).length,
        });
      }),
  );

  // ---------- list_all_secrets ----------
  server.registerTool(
    "list_all_secrets",
    {
      title: "List every server's secret keys",
      description:
        "Inventory of which servers have which secret KEYS (never the values), with per-key metadata. Useful for auditing what credentials are stored, finding orphan secrets, and spotting expired credentials.",
      inputSchema: {},
    },
    async () =>
      withSecretsLock(async () => {
        const meta = await secrets.listAllMeta();
        const totalKeys = Object.values(meta).reduce((n, arr) => n + arr.length, 0);
        const expired = Object.values(meta).reduce(
          (n, arr) => n + arr.filter((e) => e.expired).length,
          0,
        );
        const by_server: Record<string, string[]> = {};
        for (const [s, arr] of Object.entries(meta)) by_server[s] = arr.map((e) => e.key);
        return jsonText({
          servers_with_secrets: Object.keys(meta).length,
          total_secret_keys: totalKeys,
          expired_count: expired,
          by_server,
          by_server_meta: meta,
        });
      }),
  );

  // ---------- delete_secret ----------
  server.registerTool(
    "delete_secret",
    {
      title: "Delete a stored secret",
      description:
        "Remove ONE secret (server + key). Returns { removed: true } if it existed, { removed: false } otherwise.\n\nMistakes to avoid:\n  - This deletes ONE key for ONE server. To remove every secret for a server, use remove_server (which also removes the inventory entry).\n  - removed: false is not an error — it means the key wasn't there. Don't retry.",
      inputSchema: {
        server: z.string(),
        key: z.string(),
      },
    },
    async ({ server: srv, key }) =>
      withSecretsLock(async () => {
        const removed = await secrets.delete(srv, key);
        await audit({ tool: "delete_secret", server: srv, key, ok: true, extra: { removed } });
        return jsonText({ server: srv, key, removed });
      }),
  );

  // ---------- audit_tail ----------
  server.registerTool(
    "audit_tail",
    {
      title: "Read the tail of the audit log",
      description:
        "Return the last N entries (default 50, max 1000) of the append-only audit log. Each entry is one JSON line recording: timestamp, tool name, server, key (no values), ok, and any error message. Use this to answer 'what did the agent change recently?' without parsing the file yourself.",
      inputSchema: {
        limit: z.number().int().positive().max(1000).optional(),
      },
    },
    async ({ limit }) => {
      const cap = limit ?? 50;
      const filePath = resolveAuditLogPath();
      let raw: string;
      try {
        raw = await fs.readFile(filePath, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          return jsonText({ path: filePath, entries: [], note: "audit log does not exist yet" });
        }
        throw err;
      }
      const lines = raw.split("\n").filter((l) => l.trim().length > 0);
      const slice = lines.slice(-cap);
      const entries = slice.map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return { raw: l };
        }
      });
      return jsonText({ path: filePath, total_lines: lines.length, entries });
    },
  );

  // ---------- ssh_check ----------
  server.registerTool(
    "ssh_check",
    {
      title: "Probe reachability of one or many servers",
      description:
        "Run a non-interactive ssh probe (`ssh -o BatchMode=yes <target> true`) against one or many servers and classify the outcome per host: ok / auth_failed / dns_failure / refused / timeout / host_key_mismatch / unreachable / unknown. Pass exactly one of name / group / tag — omit all three to probe the entire inventory. BatchMode prevents password prompts so this is safe to run unattended. Useful before 'audit all <group> servers' to skip dead hosts and surface auth problems early.\n\nMistakes to avoid:\n  - This is READ-ONLY. It does not run user commands on the host. For that you want exec_on.\n  - Probing every server can take ~ConnectTimeout × ceil(count/parallel) in the worst case. Set connect_timeout_sec aggressively (2–3s) on big inventories.\n  - 'auth_failed' on a host means BatchMode blocked an interactive prompt — the host is reachable, you just don't have a key configured. Don't classify it as 'down'.",
      inputSchema: {
        name: z.string().optional(),
        group: z.string().optional(),
        tag: z.string().optional(),
        connect_timeout_sec: z.number().int().positive().max(60).optional(),
        hard_timeout_ms: z.number().int().positive().max(120_000).optional(),
        parallel: z.number().int().positive().max(64).optional(),
      },
    },
    async ({ name, group, tag, connect_timeout_sec, hard_timeout_ms, parallel }) =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        const provided = [name, group, tag].filter(Boolean).length;
        if (provided > 1) {
          return errorText(
            "Provide at most one of: name, group, tag. " +
              "(Omit all three to probe the entire inventory.)",
          );
        }
        let targets: Server[];
        if (name) {
          const s = store.get(name);
          if (!s) {
            return errorText(
              `Server "${name}" not found. Call list_servers to see what's defined.`,
            );
          }
          targets = [s];
        } else if (group) {
          targets = store.list({ group });
          if (targets.length === 0) {
            return errorText(
              `No servers in group "${group}". Call list_groups to see what's defined.`,
            );
          }
        } else if (tag) {
          targets = store.list({ tag });
          if (targets.length === 0) {
            return errorText(
              `No servers with tag "${tag}". Call list_tags to see what's defined.`,
            );
          }
        } else {
          targets = store.all();
        }
        if (targets.length === 0) {
          return jsonText({ count: 0, results: [], by_outcome: {} });
        }
        const results = await sshCheckMany(targets, {
          connect_timeout_sec,
          hard_timeout_ms,
          parallel,
        });
        const byOutcome: Record<string, number> = {};
        for (const r of results) byOutcome[r.outcome] = (byOutcome[r.outcome] ?? 0) + 1;
        return jsonText({
          count: results.length,
          ok_count: byOutcome.ok ?? 0,
          by_outcome: byOutcome,
          results,
        });
      }),
  );

  // ---------- exec_on ----------
  server.registerTool(
    "exec_on",
    {
      title: "Run a command across one or many servers",
      description:
        "Execute a non-interactive shell command on one or many servers via ssh and return per-host exit_code, stdout, stderr. Pass exactly one of name / group / tag.\n\nTWO-STEP DEFAULT (agents make scope mistakes — this is the guard):\n  Step 1: call with dry_run omitted or dry_run:true. The tool runs ssh_check on the target set and returns a PLAN — list of resolved targets and per-host reachability outcome. No remote command is sent.\n  Step 2: inspect the plan. Confirm the target count is what you intended. Then call again with dry_run:false to actually execute.\n\nSTRICTLY OPT-IN at the system level: refuses unless SERVER_INVENTORY_ALLOW_EXEC=1 is set in the MCP server's environment, dry_run or not. Output is truncated per host (default 4 KB stdout + 4 KB stderr). The audit log records server + exit code only — never the command body, never the output (both can carry credentials or PII).\n\nMistakes to avoid:\n  - Skipping the dry_run step on big groups. A typo in the command can trash every host before you read the first error.\n  - Inlining a secret value into the command (`echo MyP@ss | sudo -S ...`). The command argument is visible in `ps` on the remote and is part of your prompt context locally. Better: have your ssh tool pipe the secret in via stdin from outside the remote-command boundary.\n  - Using shell `&&` chains for multi-step audits. If step 1 fails on host A but step 2 succeeds on host B (because A was unreachable), your aggregation logic gets confused. Use exec_on once per step and aggregate per host.\n  - Treating timed_out as 'host is down'. timed_out means the WHOLE ssh invocation ran past hard_timeout_ms — the remote command may have started.",
      inputSchema: {
        command: z
          .string()
          .min(1)
          .describe(
            "The command to run, as a single string. ssh forwards it to the remote login shell so normal shell quoting / pipes / redirects work. NEVER inline a secret value here.",
          ),
        name: z.string().optional(),
        group: z.string().optional(),
        tag: z.string().optional(),
        dry_run: z
          .boolean()
          .optional()
          .describe(
            "Default true. When true, returns a reachability plan instead of executing. Pass false ONLY after you have inspected the plan and confirmed the scope.",
          ),
        connect_timeout_sec: z.number().int().positive().max(60).optional(),
        hard_timeout_ms: z.number().int().positive().max(600_000).optional(),
        parallel: z.number().int().positive().max(32).optional(),
        max_output_bytes: z.number().int().positive().max(1024 * 1024).optional(),
      },
    },
    async ({
      command,
      name,
      group,
      tag,
      dry_run,
      connect_timeout_sec,
      hard_timeout_ms,
      parallel,
      max_output_bytes,
    }) =>
      withInventoryLock(async () => {
        if (!execEnabled()) {
          return errorText(
            "exec_on is disabled. Set SERVER_INVENTORY_ALLOW_EXEC=1 in the environment that starts " +
              "this MCP server to enable it. This is opt-in because exec_on lets an agent run arbitrary " +
              "commands on every host in a group.",
          );
        }
        const store = await InventoryStore.open();
        const provided = [name, group, tag].filter(Boolean).length;
        if (provided !== 1) {
          return errorText(
            "Provide exactly one of: name, group, tag. " +
              "(Use list_groups / list_tags to discover what's defined, or list_servers to pick a name.)",
          );
        }
        let targets: Server[];
        if (name) {
          const s = store.get(name);
          if (!s) {
            return errorText(
              `Server "${name}" not found. Call list_servers to see what's defined, or add_server if "${name}" is new.`,
            );
          }
          targets = [s];
        } else if (group) {
          targets = store.list({ group });
          if (targets.length === 0) {
            return errorText(
              `No servers in group "${group}". Call list_groups to see what's defined.`,
            );
          }
        } else {
          targets = store.list({ tag: tag! });
          if (targets.length === 0) {
            return errorText(
              `No servers with tag "${tag}". Call list_tags to see what's defined.`,
            );
          }
        }

        const isDryRun = dry_run !== false; // default: true
        if (isDryRun) {
          const probe = await sshCheckMany(targets, {
            connect_timeout_sec,
            hard_timeout_ms,
            parallel,
          });
          const byOutcome: Record<string, number> = {};
          for (const r of probe) byOutcome[r.outcome] = (byOutcome[r.outcome] ?? 0) + 1;
          const okCount = byOutcome.ok ?? 0;
          await audit({
            tool: "exec_on:dry_run",
            ok: true,
            extra: { target_count: targets.length, ok_count: okCount },
          });
          return jsonText({
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
                ? "ZERO hosts are reachable. Do NOT call exec_on with dry_run:false — there is nothing to run on. Fix the inventory / connectivity first."
                : `${okCount} of ${targets.length} hosts are reachable. If the target list and command are what you intended, call exec_on again with dry_run:false and the same name/group/tag to execute. Unreachable hosts will still be attempted and will return their error class instead of stdout — pre-filter via ssh_check if you want to skip them.`,
          });
        }

        const results = await execOn(targets, command, {
          connect_timeout_sec,
          hard_timeout_ms,
          parallel,
          max_output_bytes,
        });
        for (const r of results) {
          await audit({
            tool: "exec_on",
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
        return jsonText({
          dry_run: false,
          count: results.length,
          ok_count: okCount,
          fail_count: results.length - okCount,
          results,
        });
      }),
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr so it doesn't corrupt the stdio protocol on stdout.
  process.stderr.write(
    `[${PKG_NAME}] ready — inventory: ${resolveInventoryPath()}\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`[${PKG_NAME}] fatal: ${(err as Error).message}\n`);
  process.exit(1);
});
