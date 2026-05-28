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
const secretsPath = path.join(
  os.tmpdir(),
  `server-inventory-smoke-${process.pid}.enc`,
);
const auditPath = path.join(
  os.tmpdir(),
  `server-inventory-smoke-${process.pid}.audit.log`,
);

await fs.rm(inventoryPath, { force: true });
await fs.rm(secretsPath, { force: true });
await fs.rm(auditPath, { force: true });

const child = spawn("node", [entry], {
  env: {
    ...process.env,
    SERVER_INVENTORY_PATH: inventoryPath,
    SERVER_INVENTORY_SECRETS_PATH: secretsPath,
    SERVER_INVENTORY_AUDIT_LOG: auditPath,
    // Force the env-passphrase backend so the smoke test never touches
    // the real Keychain on developer machines.
    SERVER_INVENTORY_PASSPHRASE: "smoke-test-passphrase-" + process.pid,
  },
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
    tools.result.tools.length >= 20,
    `tools/list returns at least 20 tools (got ${tools.result.tools.length})`,
  );
  const toolNames = new Set(tools.result.tools.map((t) => t.name));
  assert(toolNames.has("ssh_check"), "tools/list includes ssh_check");
  assert(toolNames.has("exec_on"), "tools/list includes exec_on");

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

  // ---------- secrets ----------
  const secInfo = await call("secrets_info", {});
  assert(
    secInfo.backend.startsWith("encrypted-file"),
    `secrets_info reports encrypted-file backend (got ${secInfo.backend})`,
  );

  const setRes = await call("set_secret", {
    server: "lp-web-1",
    key: "password",
    value: "hunter2",
  });
  assert(setRes.stored === true, "set_secret stores a value");
  assert(setRes.value_length === 7, "set_secret reports value_length");

  const getRes = await call("get_secret", {
    server: "lp-web-1",
    key: "password",
  });
  assert(getRes.value === "hunter2", "get_secret round-trips the stored value");

  const missing = await call("get_secret", {
    server: "lp-web-1",
    key: "nope",
  });
  assert(missing.value === null, "get_secret returns null for missing keys");

  await call("set_secret", { server: "lp-web-1", key: "sudo_password", value: "rootbeer" });
  // Add lp-other to the inventory before we exercise rename-migrates-secrets
  // below; setting a secret for a name that has no inventory row is still
  // legal (e.g. you're about to add the server) but rename works against
  // the inventory record.
  await call("add_server", { name: "lp-other", host: "lp-other.example", groups: ["misc"] });
  await call("set_secret", { server: "lp-other", key: "api_token", value: "abc-123" });

  const listed = await call("list_secrets", { server: "lp-web-1" });
  assert(listed.count === 2 && listed.keys.includes("password") && listed.keys.includes("sudo_password"),
    "list_secrets shows both stored keys for lp-web-1");

  const all = await call("list_all_secrets", {});
  assert(all.servers_with_secrets === 2, "list_all_secrets sees 2 servers");
  assert(all.total_secret_keys === 3, "list_all_secrets sees 3 keys total");

  // get_server should now include secret keys
  const gotWithSecrets = await call("get_server", { name: "lp-web-1" });
  assert(
    gotWithSecrets.secrets.keys.length === 2,
    `get_server.secrets.keys lists stored secret names (got ${JSON.stringify(gotWithSecrets.secrets.keys)})`,
  );

  // list_servers should expose the count
  const listedAgain = await call("list_servers", {});
  const lpRow = listedAgain.servers.find((s) => s.name === "lp-web-1");
  assert(lpRow.secret_count === 2, "list_servers.secret_count reflects stored secrets");

  // Encrypted file must not contain plaintext secrets
  const fileRaw = await fs.readFile(secretsPath, "utf8");
  assert(!fileRaw.includes("hunter2"), "secrets file does not contain plaintext password");
  assert(!fileRaw.includes("rootbeer"), "secrets file does not contain plaintext sudo password");
  assert(!fileRaw.includes("abc-123"), "secrets file does not contain plaintext api token");

  const del = await call("delete_secret", { server: "lp-web-1", key: "sudo_password" });
  assert(del.removed === true, "delete_secret removes the key");

  const delMissing = await call("delete_secret", { server: "lp-web-1", key: "sudo_password" });
  assert(delMissing.removed === false, "delete_secret returns false for missing keys");

  // remove_server should cascade-delete secrets
  await call("add_server", { name: "lp-doomed", host: "x", groups: ["test"] });
  await call("set_secret", { server: "lp-doomed", key: "k1", value: "v1" });
  await call("set_secret", { server: "lp-doomed", key: "k2", value: "v2" });
  const rm2 = await call("remove_server", { name: "lp-doomed" });
  assert(rm2.removed_secret_count === 2, "remove_server cascades to delete 2 secrets");
  const afterCascade = await call("list_secrets", { server: "lp-doomed" });
  assert(afterCascade.count === 0, "no secrets remain for the removed server");

  // rename should migrate secrets
  await call("update_server", { name: "lp-other", rename_to: "lp-renamed" });
  const oldHasNone = await call("list_secrets", { server: "lp-other" });
  const newHasIt = await call("list_secrets", { server: "lp-renamed" });
  assert(oldHasNone.count === 0, "rename clears secrets under the old name");
  assert(
    newHasIt.keys.includes("api_token"),
    "rename migrates secrets to the new name",
  );

  // ---------- paths_report + validate_inventory ----------
  const report = await call("paths_report", {});
  assert(report.inventory.path === inventoryPath, "paths_report.inventory.path matches");
  assert(report.secrets.path === secretsPath, "paths_report.secrets.path matches");
  assert(typeof report.secrets.backend === "string", "paths_report.secrets.backend is set");
  assert(Array.isArray(report.per_server), "paths_report.per_server is an array");
  assert(
    report.per_server.some((r) => r.name === "lp-web-1"),
    "paths_report.per_server lists lp-web-1",
  );

  // Add a server with a bogus identity_file and validate
  await call("add_server", {
    name: "bad-key-server",
    host: "x.example",
    identity_file: "/this/path/definitely/does/not/exist",
    groups: ["test"],
  });
  const validation = await call("validate_inventory", {});
  const badEntry = validation.problems.find(
    (p) => p.server === "bad-key-server" && p.severity === "error",
  );
  assert(!!badEntry, "validate_inventory flags missing identity_file as error");
  await call("remove_server", { name: "bad-key-server" });

  // ---------- secret metadata + expiry ----------
  const metaRes = await call("set_secret", {
    server: "lp-web-1",
    key: "rotated_token",
    value: "shhh-rotate-me",
    expires_in: "30d",
  });
  assert(
    typeof metaRes.created_at === "string" && typeof metaRes.updated_at === "string",
    "set_secret returns created_at + updated_at",
  );
  assert(typeof metaRes.expires_at === "string", "set_secret with expires_in returns expires_at");
  assert(metaRes.expired === false, "freshly-set secret with future expiry is not expired");

  // Updating preserves created_at and bumps updated_at.
  const meta2 = await call("set_secret", {
    server: "lp-web-1",
    key: "rotated_token",
    value: "shhh-again",
  });
  assert(meta2.created_at === metaRes.created_at, "update preserves created_at");
  assert(meta2.updated_at !== metaRes.updated_at, "update bumps updated_at");

  // list_secrets now exposes metadata as well as the raw key list.
  const listed2 = await call("list_secrets", { server: "lp-web-1" });
  assert(
    Array.isArray(listed2.entries) && listed2.entries.some((e) => e.key === "rotated_token"),
    "list_secrets.entries carries per-key metadata",
  );

  // Expired credentials should be flagged by validate_inventory.
  const longAgo = new Date(Date.now() - 86_400_000).toISOString();
  await call("set_secret", {
    server: "lp-web-1",
    key: "stale_creds",
    value: "x",
    expires_at: longAgo,
  });
  const validationExpired = await call("validate_inventory", {});
  assert(
    validationExpired.problems.some(
      (p) => p.server === "lp-web-1" && /expired/i.test(p.message),
    ),
    "validate_inventory flags expired secrets",
  );
  await call("delete_secret", { server: "lp-web-1", key: "stale_creds" });
  await call("delete_secret", { server: "lp-web-1", key: "rotated_token" });

  // ---------- ssh_check ----------
  // .invalid is RFC 2606 — guaranteed never to resolve, fast DNS failure.
  await call("add_server", {
    name: "unreachable",
    host: "nope.invalid",
    groups: ["smoke"],
  });
  const probe = await call("ssh_check", {
    name: "unreachable",
    connect_timeout_sec: 2,
    hard_timeout_ms: 8000,
  });
  assert(probe.count === 1, "ssh_check returns one result for a single target");
  const probeResult = probe.results[0];
  assert(
    probeResult.outcome !== "ok",
    `ssh_check on .invalid should not be ok (got ${probeResult.outcome})`,
  );
  // The dns_failure path is the most common verdict, but on some sandboxed
  // CI runners ssh may report timeout instead. Accept either as long as the
  // classification ran.
  assert(
    ["dns_failure", "timeout", "unreachable", "unknown"].includes(probeResult.outcome),
    `ssh_check classified the failure (got ${probeResult.outcome})`,
  );
  await call("remove_server", { name: "unreachable" });

  // ---------- exec_on (gated) ----------
  const execRefused = await call("exec_on", {
    name: "lp-web-1",
    command: "true",
  });
  assert(
    typeof execRefused.error === "string" && /SERVER_INVENTORY_ALLOW_EXEC/.test(execRefused.error),
    "exec_on refuses without SERVER_INVENTORY_ALLOW_EXEC (dry_run unspecified)",
  );
  // The gate also applies when dry_run is explicitly requested — the dry
  // run is informative but still requires the operator to have enabled the
  // tool. This keeps the threat model simple: ALLOW_EXEC controls whether
  // the tool is functional at all.
  const dryRefused = await call("exec_on", {
    name: "lp-web-1",
    command: "true",
    dry_run: true,
  });
  assert(
    typeof dryRefused.error === "string" && /SERVER_INVENTORY_ALLOW_EXEC/.test(dryRefused.error),
    "exec_on dry_run also gated by ALLOW_EXEC",
  );

  // ---------- audit log ----------
  const tail = await call("audit_tail", { limit: 200 });
  assert(tail.entries.length > 0, "audit_tail returns recorded entries");
  assert(
    tail.entries.some((e) => e.tool === "add_server" && e.server === "lp-web-1"),
    "audit log records add_server for lp-web-1",
  );
  assert(
    tail.entries.some((e) => e.tool === "set_secret" && e.key === "password"),
    "audit log records set_secret (key only, no value)",
  );
  assert(
    tail.entries.some((e) => e.tool === "remove_server" && e.ok === true),
    "audit log records successful remove_server",
  );
  // The file itself must contain no secret values
  const auditRaw = await fs.readFile(auditPath, "utf8");
  assert(!auditRaw.includes("hunter2"), "audit log does not contain secret values");
  assert(!auditRaw.includes("rootbeer"), "audit log does not contain sudo passwords");
  assert(!auditRaw.includes("abc-123"), "audit log does not contain api tokens");

  console.log("\nAll smoke checks passed.");
} catch (err) {
  console.error("Smoke test failed:", err.message);
  process.exitCode = 1;
} finally {
  child.kill();
  await once(child, "exit").catch(() => {});
  await fs.rm(inventoryPath, { force: true });
  await fs.rm(secretsPath, { force: true });
  await fs.rm(auditPath, { force: true });
}
