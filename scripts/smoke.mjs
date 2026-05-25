#!/usr/bin/env node
// Smoke test: spawns dist/index.js, speaks JSON-RPC over stdio, exercises
// every tool against a throwaway inventory file in the system tmp dir.
//
//   node scripts/smoke.mjs
//
// Exits 0 on success, non-zero on any assertion failure.

import { spawn } from "node:child_process";
import { once } from "node:events";
import readline from "node:readline";
import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const entry = path.resolve(here, "..", "dist", "index.js");
const inventoryPath = path.join(
  os.tmpdir(),
  `server-inventory-smoke-${process.pid}.json`,
);

await fs.rm(inventoryPath, { force: true });

const child = spawn("node", [entry], {
  env: { ...process.env, SERVER_INVENTORY_PATH: inventoryPath },
  stdio: ["pipe", "pipe", "inherit"],
});

const rl = readline.createInterface({ input: child.stdout });
const pending = new Map();
rl.on("line", (l) => {
  if (!l.trim()) return;
  try {
    const o = JSON.parse(l);
    if (o.id != null && pending.has(o.id)) pending.get(o.id)(o);
  } catch {
    // ignore non-JSON lines
  }
});

let nextId = 1;
function rpc(method, params, expectReply = true) {
  if (!expectReply) {
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
    return Promise.resolve();
  }
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timeout: ${method}`)), 5000);
    pending.set(id, (msg) => {
      clearTimeout(t);
      pending.delete(id);
      resolve(msg);
    });
    child.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
    );
  });
}

async function call(name, args) {
  const r = await rpc("tools/call", { name, arguments: args });
  if (r.error) throw new Error(`${name} errored: ${JSON.stringify(r.error)}`);
  const text = r.result?.content?.[0]?.text;
  if (!text) throw new Error(`${name}: no text content`);
  if (r.result.isError) return { error: text };
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

function assert(cond, msg) {
  if (!cond) {
    console.error(`✗ ${msg}`);
    process.exitCode = 1;
    throw new Error(msg);
  }
  console.log(`✓ ${msg}`);
}

try {
  await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "smoke", version: "1" },
  });
  await rpc("notifications/initialized", {}, false);

  const tools = await rpc("tools/list", {});
  assert(
    tools.result.tools.length >= 9,
    `tools/list returns at least 9 tools (got ${tools.result.tools.length})`,
  );

  const info0 = await call("inventory_info", {});
  assert(info0.server_count === 0, "starts with an empty inventory");

  const add1 = await call("add_server", {
    name: "lp-web-1",
    host: "10.0.0.5",
    user: "ubuntu",
    groups: ["logicplanes", "production"],
    tags: ["web", "nginx"],
    environment: "production",
    role: "web",
    description: "primary web",
  });
  assert(add1.added.name === "lp-web-1", "add_server returns the created entry");

  const add2 = await call("add_server", {
    name: "lp-db-1",
    ssh_alias: "lp-db-1",
    groups: ["logicplanes", "production"],
    tags: ["db", "postgres"],
    environment: "production",
    role: "db",
  });
  assert(add2.added.ssh.command === "ssh lp-db-1", "ssh_alias short-circuits to plain ssh <alias>");

  const dup = await call("add_server", { name: "lp-web-1", host: "x" });
  assert(dup.error?.includes("already exists"), "duplicate add is rejected");

  const listLp = await call("list_servers", { group: "logicplanes" });
  assert(listLp.count === 2, "group filter returns 2 logicplanes servers");

  const targets = await call("ssh_target_for", { group: "logicplanes" });
  assert(targets.count === 2, "ssh_target_for resolves 2 targets for the group");
  const webRow = targets.targets.find((t) => t.name === "lp-web-1");
  assert(
    webRow?.command === "ssh ubuntu@10.0.0.5",
    "host+user entry produces user@host ssh command",
  );

  const groups = await call("list_groups", {});
  assert(
    groups.groups.some((g) => g.name === "logicplanes" && g.count === 2),
    "list_groups reports logicplanes with 2 members",
  );

  const upd = await call("update_server", {
    name: "lp-web-1",
    tags: ["web", "nginx", "tls"],
    port: 2222,
  });
  assert(
    upd.updated.ssh.command === "ssh -p 2222 ubuntu@10.0.0.5",
    "update_server: port is reflected in the ssh command",
  );

  const got = await call("get_server", { name: "lp-web-1" });
  assert(got.tags.includes("tls"), "get_server returns updated tags");

  const rm = await call("remove_server", { name: "lp-db-1" });
  assert(rm.removed === "lp-db-1", "remove_server returns the removed name");

  const finalList = await call("list_servers", {});
  assert(finalList.count === 1, "exactly one server remains");

  console.log("\nAll smoke checks passed.");
} catch (err) {
  console.error("Smoke test failed:", err.message);
  process.exitCode = 1;
} finally {
  child.kill();
  await once(child, "exit").catch(() => {});
  await fs.rm(inventoryPath, { force: true });
}
