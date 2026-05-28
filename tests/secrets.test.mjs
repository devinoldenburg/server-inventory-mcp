import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  EncryptedFileSecretsStore,
  EnvPassphraseMasterKey,
  SECRETS_DATA_VERSION,
  parseExpiresIn,
  safeEquals,
} from "../dist/secrets.js";

function tmpFile(name) {
  return path.join(
    os.tmpdir(),
    `sec-${process.pid}-${Math.random().toString(16).slice(2)}-${name}`,
  );
}

function withPassphrase(value) {
  const previous = process.env.SERVER_INVENTORY_PASSPHRASE;
  process.env.SERVER_INVENTORY_PASSPHRASE = value;
  return () => {
    if (previous === undefined) delete process.env.SERVER_INVENTORY_PASSPHRASE;
    else process.env.SERVER_INVENTORY_PASSPHRASE = previous;
  };
}

test("EncryptedFileSecretsStore round-trips values", async () => {
  const restore = withPassphrase("test-pass-1");
  const p = tmpFile("rt.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await store.set("srv-1", "password", "p4ss");
  await store.set("srv-1", "sudo_password", "rootbeer");
  await store.set("srv-2", "api_token", "abc-123");

  assert.equal(await store.get("srv-1", "password"), "p4ss");
  assert.equal(await store.get("srv-1", "missing"), null);
  assert.equal(await store.get("missing", "password"), null);
  assert.deepEqual(await store.list("srv-1"), ["password", "sudo_password"]);
  assert.deepEqual(await store.listAll(), {
    "srv-1": ["password", "sudo_password"],
    "srv-2": ["api_token"],
  });
  await fs.rm(p, { force: true });
  restore();
});

test("File never contains plaintext", async () => {
  const restore = withPassphrase("test-pass-2");
  const p = tmpFile("plain.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  const secret = "totally-distinctive-marker-12345";
  await store.set("srv", "k", secret);
  const raw = await fs.readFile(p, "utf8");
  assert.ok(!raw.includes(secret), "raw file does not contain plaintext");
  assert.ok(!raw.includes("totally-distinctive"), "no partial leak either");
  await fs.rm(p, { force: true });
  restore();
});

test("Tamper detection: flipped ciphertext fails to decrypt", async () => {
  const restore = withPassphrase("test-pass-3");
  const p = tmpFile("tamper.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await store.set("srv", "k", "value");
  const wrapper = JSON.parse(await fs.readFile(p, "utf8"));
  // Flip a byte of the ciphertext (use first two chars so we always change the value)
  const flipped = (parseInt(wrapper.ciphertext.slice(0, 2), 16) ^ 0xff)
    .toString(16)
    .padStart(2, "0");
  wrapper.ciphertext = flipped + wrapper.ciphertext.slice(2);
  await fs.writeFile(p, JSON.stringify(wrapper));
  await assert.rejects(
    () => store.get("srv", "k"),
    /Failed to decrypt/,
    "tampered file refuses to decrypt",
  );
  await fs.rm(p, { force: true });
  restore();
});

test("Wrong passphrase fails to decrypt", async () => {
  const p = tmpFile("wrong-pass.enc");
  await fs.rm(p, { force: true });
  const r1 = withPassphrase("right-passphrase");
  const storeRight = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await storeRight.set("srv", "k", "v");
  r1();

  const r2 = withPassphrase("wrong-passphrase");
  const storeWrong = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await assert.rejects(() => storeWrong.get("srv", "k"), /Failed to decrypt/);
  r2();

  await fs.rm(p, { force: true });
});

test("delete and deleteServer", async () => {
  const restore = withPassphrase("test-pass-4");
  const p = tmpFile("del.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await store.set("a", "k1", "v1");
  await store.set("a", "k2", "v2");
  await store.set("b", "k1", "v1");
  assert.equal(await store.delete("a", "k1"), true);
  assert.equal(await store.delete("a", "k1"), false, "second delete returns false");
  assert.deepEqual(await store.list("a"), ["k2"]);
  assert.equal(await store.deleteServer("a"), 1);
  assert.deepEqual(await store.listAll(), { b: ["k1"] });
  await fs.rm(p, { force: true });
  restore();
});

test("set rejects empty values", async () => {
  const restore = withPassphrase("test-pass-5");
  const p = tmpFile("empty.enc");
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await assert.rejects(() => store.set("a", "k", ""), /non-empty/);
  await fs.rm(p, { force: true });
  restore();
});

test("safeEquals constant-time helper", () => {
  assert.equal(safeEquals("abc", "abc"), true);
  assert.equal(safeEquals("abc", "abd"), false);
  assert.equal(safeEquals("abc", "abcd"), false);
});

// ---------- v2: metadata, expiry, rename, migration ----------

test("set attaches created_at and updated_at; update bumps updated_at only", async () => {
  const restore = withPassphrase("test-pass-meta");
  const p = tmpFile("meta.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await store.set("srv", "k", "v1");
  const first = await store.getMeta("srv", "k");
  assert.ok(first);
  assert.equal(typeof first.created_at, "string");
  assert.equal(first.created_at, first.updated_at);
  assert.equal(first.expired, false);
  assert.equal(first.expires_at, undefined);

  // Force a measurable time gap. Node's Date.now() resolution is 1ms; 5ms is
  // plenty for the inequality to be unambiguous on every platform.
  await new Promise((r) => setTimeout(r, 5));
  await store.set("srv", "k", "v2");
  const second = await store.getMeta("srv", "k");
  assert.equal(second.created_at, first.created_at, "created_at is preserved across updates");
  assert.notEqual(second.updated_at, first.updated_at, "updated_at is bumped on update");
  assert.equal(await store.get("srv", "k"), "v2");
  await fs.rm(p, { force: true });
  restore();
});

test("expires_at via absolute timestamp + isExpired", async () => {
  const restore = withPassphrase("test-pass-expiry");
  const p = tmpFile("expiry.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  const past = new Date(Date.now() - 60_000).toISOString();
  const future = new Date(Date.now() + 60_000).toISOString();
  await store.set("srv", "expired-key", "v", { expires_at: past });
  await store.set("srv", "live-key", "v", { expires_at: future });
  const all = await store.listMeta("srv");
  const expired = all.find((e) => e.key === "expired-key");
  const live = all.find((e) => e.key === "live-key");
  assert.equal(expired.expired, true);
  assert.equal(live.expired, false);
  // clearing expiry with null
  await store.set("srv", "expired-key", "v2", { expires_at: null });
  const cleared = await store.getMeta("srv", "expired-key");
  assert.equal(cleared.expires_at, undefined);
  assert.equal(cleared.expired, false);
  await fs.rm(p, { force: true });
  restore();
});

test("rename moves all keys in a single write", async () => {
  const restore = withPassphrase("test-pass-rename");
  const p = tmpFile("rename.enc");
  await fs.rm(p, { force: true });
  const store = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  await store.set("old-name", "k1", "v1");
  await store.set("old-name", "k2", "v2");
  await store.set("old-name", "k3", "v3");
  await store.set("untouched", "x", "y");

  const mtimeBefore = (await fs.stat(p)).mtimeMs;
  await new Promise((r) => setTimeout(r, 5));
  const moved = await store.rename("old-name", "new-name");
  const mtimeAfter = (await fs.stat(p)).mtimeMs;

  assert.equal(moved, 3, "rename returns the number of keys moved");
  assert.ok(mtimeAfter > mtimeBefore, "file was touched exactly once");
  assert.deepEqual(await store.list("old-name"), []);
  assert.deepEqual(await store.list("new-name"), ["k1", "k2", "k3"]);
  assert.equal(await store.get("new-name", "k2"), "v2");
  assert.deepEqual(await store.list("untouched"), ["x"]);
  // Renaming a missing source is a no-op, not an error.
  assert.equal(await store.rename("does-not-exist", "anything"), 0);
  // Renaming into a server that already has secrets is an error.
  await assert.rejects(() => store.rename("untouched", "new-name"), /already has stored secrets/);
  await fs.rm(p, { force: true });
  restore();
});

test("v1 file is migrated transparently on read; rewrite stamps data_version 2", async () => {
  const restore = withPassphrase("test-pass-migrate");
  const p = tmpFile("v1.enc");
  await fs.rm(p, { force: true });

  // Hand-build a v1 file: encrypted blob with the OLD shape and no data_version.
  // Reuse the same store class to do the encryption — we write directly via
  // the internal-format-by-injection path: insert into v2, then mutate the
  // wrapper to look like v1 on disk.
  const seedStore = new EncryptedFileSecretsStore(p, new EnvPassphraseMasterKey());
  // Trick: write the v1 shape inside the encrypted payload by hand.
  const { randomBytes, createCipheriv, scryptSync } = await import("node:crypto");
  const key = scryptSync("test-pass-migrate", Buffer.from("server-inventory-mcp:v1:scrypt-salt"), 32, {
    N: 1 << 15,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  const v1Map = { srv: { password: "old-plaintext", api_token: "tok" } };
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from("server-inventory-mcp:v1"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(v1Map), "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const wrapper = {
    version: 1,
    algorithm: "aes-256-gcm",
    // NOTE: no data_version field — that's what makes this a "v1" file.
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    ciphertext: ciphertext.toString("hex"),
  };
  await fs.writeFile(p, JSON.stringify(wrapper, null, 2), { mode: 0o600 });

  // Read it back through the new store. Values must come back via .get().
  assert.equal(await seedStore.get("srv", "password"), "old-plaintext");
  assert.equal(await seedStore.get("srv", "api_token"), "tok");

  // Metadata is synthesized at migration time — created_at and updated_at
  // are populated so the agent can still reason about freshness.
  const meta = await seedStore.getMeta("srv", "password");
  assert.ok(meta);
  assert.equal(typeof meta.created_at, "string");
  assert.equal(typeof meta.updated_at, "string");
  assert.equal(meta.expired, false);

  // File on disk still has the v1 shape — migration is lazy.
  const raw1 = JSON.parse(await fs.readFile(p, "utf8"));
  assert.equal(raw1.data_version, undefined, "lazy: file untouched until first write");

  // Any write upgrades the file to v2 on disk.
  await seedStore.set("srv", "password", "rotated");
  const raw2 = JSON.parse(await fs.readFile(p, "utf8"));
  assert.equal(raw2.data_version, SECRETS_DATA_VERSION);

  const info = await seedStore.describe();
  assert.equal(info.data_version, SECRETS_DATA_VERSION);

  await fs.rm(p, { force: true });
  restore();
});

test("parseExpiresIn handles s/m/h/d/w", () => {
  const now = new Date("2026-05-01T00:00:00.000Z");
  assert.equal(parseExpiresIn("30s", now), "2026-05-01T00:00:30.000Z");
  assert.equal(parseExpiresIn("15m", now), "2026-05-01T00:15:00.000Z");
  assert.equal(parseExpiresIn("2h", now), "2026-05-01T02:00:00.000Z");
  assert.equal(parseExpiresIn("7d", now), "2026-05-08T00:00:00.000Z");
  assert.equal(parseExpiresIn("2w", now), "2026-05-15T00:00:00.000Z");
  assert.throws(() => parseExpiresIn("forever", now), /Invalid duration/);
  assert.throws(() => parseExpiresIn("10x", now), /Invalid duration/);
});
