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
  resolveSecretsPath,
  withSecretsLock,
} from "./secrets.js";
import {
  buildPathsReport,
  expandHome,
  loadSshConfigHostAliases,
} from "./paths.js";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Server } from "./schema.js";

const PKG_NAME = "server-inventory-mcp";
const PKG_VERSION = "0.2.0";

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
  const server = new McpServer(
    { name: PKG_NAME, version: PKG_VERSION },
    {
      capabilities: { tools: {} },
      instructions: [
        "This server keeps an inventory of SSH-reachable machines (grouped + tagged) plus",
        "an encrypted secret store for passwords, sudo passwords, key passphrases, db creds, etc.",
        "Discovery flow: list_groups / list_tags → list_servers → ssh_target_for or get_server →",
        "connect with the agent's own ssh tool. If the server has stored secrets (visible as",
        "secret_count in list_servers and secrets.keys in get_server), retrieve a specific value",
        "with get_secret RIGHT BEFORE the call that needs it, then pipe it directly into the",
        "command (e.g. echo \"$pw\" | sudo -S ...). Never echo or persist secret values.",
        `Inventory file: ${resolveInventoryPath()}. Secrets file: ${resolveSecretsPath()}.`,
      ].join(" "),
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
        if (!s) return errorText(`Server "${name}" not found.`);
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
        "Resolve one or more servers to ssh connection info. Pass exactly one of: name (single server), group (every server in that group), or tag. Returns the ssh target (alias or user@host) and a ready-to-run ssh command for each match — feed these to the agent's ssh tool to connect.",
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
          return errorText("Provide exactly one of: name, group, tag.");
        }
        const store = await InventoryStore.open();
        let matches: Server[];
        if (name) {
          const s = store.get(name);
          if (!s) return errorText(`Server "${name}" not found.`);
          matches = [s];
        } else if (group) {
          matches = store.list({ group });
          if (matches.length === 0) return errorText(`No servers in group "${group}".`);
        } else {
          matches = store.list({ tag: tag! });
          if (matches.length === 0) return errorText(`No servers with tag "${tag}".`);
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
        "Add a new server to the inventory. Either ssh_alias (a host alias from ~/.ssh/config) or host must be provided. Names must be unique.",
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
        const store = await InventoryStore.open();
        const created = store.add({
          ...args,
          groups: args.groups ?? [],
          tags: args.tags ?? [],
        } as Server);
        await store.save();
        const secretKeys = await secrets.list(created.name).catch(() => []);
        return jsonText({ added: detail(created, secretKeys) });
      }),
  );

  // ---------- update_server ----------
  server.registerTool(
    "update_server",
    {
      title: "Update a server",
      description:
        "Update fields on an existing server. Only the fields you pass are changed. To clear a field, pass an empty string. To rename, set 'rename_to'.",
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
        const store = await InventoryStore.open();
        const patch: Partial<Server> = { ...rest };
        if (rename_to !== undefined) patch.name = rename_to;
        const updated = store.update(name, patch);
        await store.save();
        // If renamed, migrate any associated secrets to the new name so
        // they don't orphan.
        if (rename_to && rename_to !== name) {
          await withSecretsLock(async () => {
            const keys = await secrets.list(name);
            for (const k of keys) {
              const v = await secrets.get(name, k);
              if (v !== null) {
                await secrets.set(rename_to, k, v);
                await secrets.delete(name, k);
              }
            }
          });
        }
        const secretKeys = await secrets.list(updated.name).catch(() => []);
        return jsonText({ updated: detail(updated, secretKeys) });
      }),
  );

  // ---------- remove_server ----------
  server.registerTool(
    "remove_server",
    {
      title: "Remove a server",
      description: "Delete a server from the inventory by name.",
      inputSchema: {
        name: z.string(),
      },
    },
    async ({ name }) =>
      withInventoryLock(async () => {
        const store = await InventoryStore.open();
        const removed = store.remove(name);
        await store.save();
        // Cascade: drop any secrets associated with this server.
        const removedSecrets = await withSecretsLock(() =>
          secrets.deleteServer(name).catch(() => 0),
        );
        return jsonText({
          removed: removed.name,
          removed_secret_count: removedSecrets,
        });
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
        const problems: Array<{
          server: string;
          severity: "error" | "warning";
          message: string;
        }> = [];
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
        "Encrypt and store a secret value (password, sudo password, API token, key passphrase, ...) for a server. Common keys: password, sudo_password, ssh_passphrase, db_password, api_token. The value is encrypted with AES-256-GCM at rest and never written to the inventory file. Returns only the key that was stored, never the value.",
      inputSchema: {
        server: z.string().describe("The server name from the inventory"),
        key: z
          .string()
          .min(1)
          .describe(
            "A label for this secret (e.g. 'password', 'sudo_password', 'db_password')",
          ),
        value: z.string().min(1).describe("The secret value to encrypt and store"),
      },
    },
    async ({ server: srv, key, value }) =>
      withSecretsLock(async () => {
        await secrets.set(srv, key, value);
        return jsonText({
          server: srv,
          key,
          stored: true,
          value_length: value.length,
        });
      }),
  );

  // ---------- get_secret ----------
  server.registerTool(
    "get_secret",
    {
      title: "Retrieve a stored secret",
      description:
        "Decrypt and return a secret value for a server. Use this RIGHT BEFORE feeding the value into an ssh / scp / sudo / API call — do not echo the value or persist it elsewhere. Returns null if the key does not exist.",
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
        "List the names (keys) of every secret stored for one server. Values are NEVER returned by this tool — use get_secret with a specific key to fetch a value.",
      inputSchema: {
        server: z.string(),
      },
    },
    async ({ server: srv }) =>
      withSecretsLock(async () => {
        const keys = await secrets.list(srv);
        return jsonText({ server: srv, keys, count: keys.length });
      }),
  );

  // ---------- list_all_secrets ----------
  server.registerTool(
    "list_all_secrets",
    {
      title: "List every server's secret keys",
      description:
        "Inventory of which servers have which secret KEYS (never the values). Useful for auditing what credentials are stored and finding orphan secrets.",
      inputSchema: {},
    },
    async () =>
      withSecretsLock(async () => {
        const all = await secrets.listAll();
        const totalKeys = Object.values(all).reduce((n, arr) => n + arr.length, 0);
        return jsonText({
          servers_with_secrets: Object.keys(all).length,
          total_secret_keys: totalKeys,
          by_server: all,
        });
      }),
  );

  // ---------- delete_secret ----------
  server.registerTool(
    "delete_secret",
    {
      title: "Delete a stored secret",
      description:
        "Remove one secret (server + key). Returns { removed: true } if it existed, { removed: false } otherwise.",
      inputSchema: {
        server: z.string(),
        key: z.string(),
      },
    },
    async ({ server: srv, key }) =>
      withSecretsLock(async () => {
        const removed = await secrets.delete(srv, key);
        return jsonText({ server: srv, key, removed });
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
