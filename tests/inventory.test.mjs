import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  InventoryStore,
  buildSshCommand,
  buildSshTarget,
  filterServers,
  loadInventory,
  normalizeServer,
  saveInventory,
} from "../dist/inventory.js";

function tmpFile(name) {
  return path.join(
    os.tmpdir(),
    `inv-${process.pid}-${Math.random().toString(16).slice(2)}-${name}`,
  );
}

test("loadInventory creates an empty file when missing", async () => {
  const p = tmpFile("missing.json");
  await fs.rm(p, { force: true });
  const inv = await loadInventory(p);
  assert.equal(inv.version, 1);
  assert.deepEqual(inv.servers, []);
  const stat = await fs.stat(p);
  assert.ok(stat.isFile(), "file was created on disk");
  await fs.rm(p, { force: true });
});

test("saveInventory writes atomically and sorts by name", async () => {
  const p = tmpFile("save.json");
  await saveInventory(
    {
      version: 1,
      servers: [
        normalizeServer({ name: "z", host: "z.example", groups: [], tags: [] }),
        normalizeServer({ name: "a", host: "a.example", groups: [], tags: [] }),
        normalizeServer({ name: "m", host: "m.example", groups: [], tags: [] }),
      ],
    },
    p,
  );
  const raw = await fs.readFile(p, "utf8");
  const parsed = JSON.parse(raw);
  assert.deepEqual(parsed.servers.map((s) => s.name), ["a", "m", "z"]);
  await fs.rm(p, { force: true });
});

test("normalizeServer rejects entries with neither ssh_alias nor host", () => {
  assert.throws(
    () => normalizeServer({ name: "x", groups: [], tags: [] }),
    /must define either ssh_alias or host/,
  );
});

test("normalizeServer dedupes and trims groups and tags", () => {
  const s = normalizeServer({
    name: "x",
    host: "x.example",
    groups: ["a", "a", " b "],
    tags: ["t", "t", "u"],
  });
  assert.deepEqual(s.groups, ["a", "b"]);
  assert.deepEqual(s.tags, ["t", "u"]);
});

test("schema rejects empty-string tags before normalization", () => {
  assert.throws(
    () =>
      normalizeServer({
        name: "x",
        host: "x.example",
        groups: [],
        tags: [""],
      }),
    /at least 1 character/,
  );
});

test("filterServers — group, tag, environment, search", () => {
  const servers = [
    normalizeServer({
      name: "lp-web-1",
      host: "10.0.0.5",
      groups: ["logicplanes", "production"],
      tags: ["web"],
      environment: "production",
    }),
    normalizeServer({
      name: "lp-staging-1",
      host: "10.0.0.6",
      groups: ["logicplanes", "staging"],
      tags: ["web"],
      environment: "staging",
    }),
    normalizeServer({
      name: "other",
      host: "x.example",
      groups: ["misc"],
      tags: ["db"],
    }),
  ];
  assert.deepEqual(
    filterServers(servers, { group: "logicplanes" }).map((s) => s.name),
    ["lp-web-1", "lp-staging-1"],
  );
  assert.deepEqual(
    filterServers(servers, { tag: "db" }).map((s) => s.name),
    ["other"],
  );
  assert.deepEqual(
    filterServers(servers, { environment: "staging" }).map((s) => s.name),
    ["lp-staging-1"],
  );
  assert.deepEqual(
    filterServers(servers, { search: "10.0.0.5" }).map((s) => s.name),
    ["lp-web-1"],
  );
});

test("buildSshTarget / buildSshCommand short-circuit on ssh_alias", () => {
  const s = normalizeServer({
    name: "x",
    ssh_alias: "x-alias",
    user: "ignored",
    port: 9999,
    identity_file: "/ignored/key",
    groups: [],
    tags: [],
  });
  assert.equal(buildSshTarget(s), "x-alias");
  // When alias present, port / identity_file / jump_host are deferred to
  // ~/.ssh/config (so they should NOT appear in the command).
  assert.equal(buildSshCommand(s), "ssh x-alias");
});

test("buildSshCommand inlines port and identity when no alias", () => {
  const s = normalizeServer({
    name: "x",
    host: "x.example",
    user: "ops",
    port: 2222,
    identity_file: "/home/user/.ssh/k",
    jump_host: "bastion@b.example",
    groups: [],
    tags: [],
  });
  assert.equal(buildSshTarget(s), "ops@x.example");
  assert.equal(
    buildSshCommand(s),
    "ssh -i /home/user/.ssh/k -o IdentitiesOnly=yes -p 2222 -J bastion@b.example ops@x.example",
  );
});

test("InventoryStore: add / get / update / remove / rename", async () => {
  const p = tmpFile("crud.json");
  await fs.rm(p, { force: true });
  const store = await InventoryStore.open(p);
  store.add({ name: "a", host: "a.example", groups: ["g"], tags: ["t"] });
  store.add({ name: "b", ssh_alias: "b", groups: ["g"], tags: [] });
  await store.save(p);

  const reopened = await InventoryStore.open(p);
  assert.equal(reopened.all().length, 2);
  assert.equal(reopened.get("a")?.host, "a.example");
  assert.equal(reopened.get("b")?.ssh_alias, "b");

  reopened.update("a", { port: 2222, tags: ["t", "new"] });
  assert.equal(reopened.get("a")?.port, 2222);
  assert.deepEqual(reopened.get("a")?.tags, ["t", "new"]);

  reopened.update("a", { name: "a2" });
  assert.equal(reopened.get("a"), undefined);
  assert.equal(reopened.get("a2")?.port, 2222);

  const removed = reopened.remove("b");
  assert.equal(removed.name, "b");
  assert.equal(reopened.all().length, 1);
  await fs.rm(p, { force: true });
});

test("InventoryStore: groups() and tags() aggregations", async () => {
  const p = tmpFile("agg.json");
  await fs.rm(p, { force: true });
  const store = await InventoryStore.open(p);
  store.add({ name: "a", host: "x", groups: ["g1", "g2"], tags: ["t1"] });
  store.add({ name: "b", host: "x", groups: ["g1"], tags: ["t1", "t2"] });
  store.add({ name: "c", host: "x", groups: [], tags: [] });
  const g = store.groups();
  assert.deepEqual(
    g.map((x) => [x.name, x.count]),
    [
      ["g1", 2],
      ["g2", 1],
    ],
  );
  const t = store.tags();
  assert.deepEqual(
    t.map((x) => [x.name, x.count]),
    [
      ["t1", 2],
      ["t2", 1],
    ],
  );
  await fs.rm(p, { force: true });
});

test("update fails on rename collision", async () => {
  const p = tmpFile("collide.json");
  await fs.rm(p, { force: true });
  const store = await InventoryStore.open(p);
  store.add({ name: "a", host: "x", groups: [], tags: [] });
  store.add({ name: "b", host: "x", groups: [], tags: [] });
  assert.throws(() => store.update("a", { name: "b" }), /already exists/);
  await fs.rm(p, { force: true });
});
