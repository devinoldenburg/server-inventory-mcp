import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  EncryptedFileSecretsStore,
  EnvPassphraseMasterKey,
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
