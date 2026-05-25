#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  InventoryStore,
  buildSshCommand,
  buildSshTarget,
  resolveInventoryPath,
  withInventoryLock,
} from "./inventory.js";
import type { Server } from "./schema.js";

const PKG_NAME = "server-inventory-mcp";
const PKG_VERSION = "0.1.0";

function summary(s: Server) {
  return {
    name: s.name,
    target: buildSshTarget(s),
    groups: s.groups,
    tags: s.tags,
    environment: s.environment ?? undefined,
    role: s.role ?? undefined,
    description: s.description ?? undefined,
  };
}

function detail(s: Server) {
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
        "This server keeps an inventory of SSH-reachable machines (grouped + tagged).",
        "Use list_servers / list_groups to discover hosts (for example: every server in the 'logicplanes' group),",
        "then call get_server or ssh_target_for to learn the exact ssh target/command,",
        "and finally connect with the agent's existing ssh tool.",
        `Inventory file: ${resolveInventoryPath()}`,
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
        const rows = store.list(args).map(summary);
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
        return jsonText(detail(s));
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
        return jsonText({ added: detail(created) });
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
        return jsonText({ updated: detail(updated) });
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
        return jsonText({ removed: removed.name });
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
        return jsonText({
          path: resolveInventoryPath(),
          server_count: all.length,
          group_count: store.groups().length,
          tag_count: store.tags().length,
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
