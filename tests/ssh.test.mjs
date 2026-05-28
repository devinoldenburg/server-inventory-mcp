import { test } from "node:test";
import assert from "node:assert/strict";
import { classifySshFailure } from "../dist/ssh.js";

// The classifier is the load-bearing piece — keep this table exhaustive,
// because every new "I got an unexpected exit message" debug session in the
// wild should land back here.
test("classifySshFailure — auth_failed", () => {
  assert.equal(
    classifySshFailure(255, "user@host: Permission denied (publickey,password).", false),
    "auth_failed",
  );
});

test("classifySshFailure — dns_failure", () => {
  assert.equal(
    classifySshFailure(255, "ssh: Could not resolve hostname nope.invalid: nodename nor servname provided, or not known", false),
    "dns_failure",
  );
});

test("classifySshFailure — refused", () => {
  assert.equal(
    classifySshFailure(255, "ssh: connect to host 127.0.0.1 port 22: Connection refused", false),
    "refused",
  );
});

test("classifySshFailure — host_key_mismatch wins over auth", () => {
  // Host key mismatch usually comes with Permission denied too; the more
  // specific classification wins.
  assert.equal(
    classifySshFailure(
      255,
      "@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@\nHost key verification failed.\nPermission denied",
      false,
    ),
    "host_key_mismatch",
  );
});

test("classifySshFailure — timeout from stderr", () => {
  assert.equal(
    classifySshFailure(255, "ssh: connect to host 192.0.2.1 port 22: Operation timed out", false),
    "timeout",
  );
});

test("classifySshFailure — timeout from killed child", () => {
  assert.equal(classifySshFailure(null, "", true), "timeout");
});

test("classifySshFailure — unreachable", () => {
  assert.equal(
    classifySshFailure(255, "ssh: connect to host 10.255.255.1 port 22: No route to host", false),
    "unreachable",
  );
});

test("classifySshFailure — unknown falls through", () => {
  assert.equal(
    classifySshFailure(123, "some other error message we haven't seen yet", false),
    "unknown",
  );
});
