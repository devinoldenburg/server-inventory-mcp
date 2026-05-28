/**
 * Live SSH probes built on top of the inventory.
 *
 *   sshCheckOne / sshCheckMany — non-interactive reachability + auth probe
 *     (`ssh -o BatchMode=yes <target> true`) with structured outcome
 *     classification (ok / auth_failed / dns_failure / refused / timeout /
 *     host_key_mismatch / unreachable / unknown).
 *
 *   execOnOne / execOn — run a single command across one or many servers
 *     in parallel, capturing exit code, stdout, stderr per host. Gated by
 *     the caller (the MCP tool refuses unless SERVER_INVENTORY_ALLOW_EXEC=1)
 *     because shipping a "run anything anywhere" RPC widens the blast
 *     radius and should be an opt-in.
 *
 * BatchMode=yes makes ssh fail fast instead of prompting for a password, so
 * we get a deterministic "auth_failed" classification rather than hanging on
 * a TTY. StrictHostKeyChecking=accept-new is the modern default that adds
 * unknown hosts to known_hosts on first connect — same behaviour ssh has on
 * a fresh laptop. Both can be overridden via extra_ssh_options.
 */
import { execFile } from "node:child_process";
import path from "node:path";
import type { Server } from "./schema.js";
import { expandHome } from "./paths.js";

export type SshCheckOutcome =
  | "ok"
  | "auth_failed"
  | "dns_failure"
  | "refused"
  | "timeout"
  | "host_key_mismatch"
  | "unreachable"
  | "unknown";

export interface SshCheckResult {
  name: string;
  /** alias or user@host that ssh was invoked with */
  target: string;
  outcome: SshCheckOutcome;
  exit_code: number | null;
  duration_ms: number;
  message: string;
  /** trimmed stderr — only on failure, capped at ~512 bytes */
  stderr?: string;
}

export interface SshCheckOptions {
  /** ssh -o ConnectTimeout=N. Default 5. */
  connect_timeout_sec?: number;
  /** Hard kill timeout for the whole ssh invocation. Default 15000 ms. */
  hard_timeout_ms?: number;
  /** Max concurrent ssh subprocesses. Default 8. */
  parallel?: number;
  /** Extra `-o key=value` args appended verbatim to every ssh call. */
  extra_ssh_options?: string[];
}

export interface ExecOnResult {
  name: string;
  target: string;
  exit_code: number | null;
  /** true iff exit_code === 0 and we didn't time out / spawn-fail */
  ok: boolean;
  duration_ms: number;
  stdout: string;
  stderr: string;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
  timed_out: boolean;
  /** Process-level spawn failure (e.g. ssh binary missing). */
  error?: string;
}

export interface ExecOnOptions {
  /** ssh -o ConnectTimeout=N. Default 5. */
  connect_timeout_sec?: number;
  /** Hard kill timeout per host. Default 30000 ms. */
  hard_timeout_ms?: number;
  /** Max concurrent ssh subprocesses. Default 4 (exec is heavier than check). */
  parallel?: number;
  /** Bytes of stdout/stderr to keep per host before truncating. Default 4096 each. */
  max_output_bytes?: number;
  /** Extra `-o key=value` args appended verbatim. */
  extra_ssh_options?: string[];
}

/** Map an exit code + stderr buffer to a structured outcome. */
export function classifySshFailure(
  exitCode: number | null,
  stderr: string,
  timedOut: boolean,
): SshCheckOutcome {
  if (timedOut) return "timeout";
  if (!stderr) return "unknown";
  // Order matters — most-specific patterns first.
  if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(stderr))
    return "host_key_mismatch";
  if (/Permission denied/i.test(stderr)) return "auth_failed";
  if (
    /Could not resolve hostname|Name or service not known|nodename nor servname|getaddrinfo|Temporary failure in name resolution/i.test(
      stderr,
    )
  )
    return "dns_failure";
  if (/Connection refused/i.test(stderr)) return "refused";
  if (/Connection timed out|Operation timed out|connect to host .* timed out/i.test(stderr))
    return "timeout";
  if (/No route to host|Network is unreachable/i.test(stderr)) return "unreachable";
  void exitCode;
  return "unknown";
}

function describeOutcome(outcome: SshCheckOutcome, stderrLine: string): string {
  switch (outcome) {
    case "ok":
      return "reachable + auth ok";
    case "auth_failed":
      return "ssh permission denied (no usable key + BatchMode blocks password prompts)";
    case "dns_failure":
      return "hostname did not resolve";
    case "refused":
      return "connection refused (sshd not listening on this port?)";
    case "timeout":
      return "no response within ConnectTimeout";
    case "host_key_mismatch":
      return "host key changed — refusing to connect (check ~/.ssh/known_hosts)";
    case "unreachable":
      return "no route to host / network unreachable";
    case "unknown":
      return stderrLine
        ? `ssh failed: ${stderrLine.slice(0, 200)}`
        : "ssh failed with no diagnostic output";
  }
}

interface BuiltSsh {
  target: string;
  argv: string[];
}

function buildSshArgv(s: Server, connectTimeoutSec: number, extra: string[] = []): BuiltSsh {
  const argv: string[] = [
    "-o",
    "BatchMode=yes",
    "-o",
    `ConnectTimeout=${connectTimeoutSec}`,
    "-o",
    "StrictHostKeyChecking=accept-new",
  ];
  for (const opt of extra) {
    argv.push("-o", opt);
  }
  if (s.ssh_alias) {
    argv.push(s.ssh_alias);
    return { target: s.ssh_alias, argv };
  }
  if (s.identity_file) {
    argv.push(
      "-i",
      path.resolve(expandHome(s.identity_file)),
      "-o",
      "IdentitiesOnly=yes",
    );
  }
  if (s.port) argv.push("-p", String(s.port));
  if (s.jump_host) argv.push("-J", s.jump_host);
  const host = s.host ?? "";
  const target = s.user ? `${s.user}@${host}` : host;
  argv.push(target);
  return { target, argv };
}

interface SshRunResult {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  spawn_error?: string;
}

function runSsh(argv: string[], hardTimeoutMs: number, maxOutputBytes: number): Promise<SshRunResult> {
  return new Promise((resolve) => {
    execFile(
      "ssh",
      argv,
      {
        timeout: hardTimeoutMs,
        // node's maxBuffer is on the raw stream — make it generous so we can
        // truncate cleanly afterwards instead of erroring out mid-stream.
        maxBuffer: Math.max(maxOutputBytes * 4, 1024 * 1024),
      },
      (err, stdout, stderr) => {
        const out = stdout ? stdout.toString() : "";
        const errOut = stderr ? stderr.toString() : "";
        if (!err) {
          resolve({ exit_code: 0, stdout: out, stderr: errOut, timed_out: false });
          return;
        }
        const killed = (err as { killed?: boolean }).killed === true;
        const signal = (err as { signal?: string | null }).signal;
        const rawCode = (err as { code?: number | string }).code;
        let exit_code: number | null = null;
        let spawn_error: string | undefined;
        if (typeof rawCode === "number") {
          exit_code = rawCode;
        } else if (typeof rawCode === "string") {
          spawn_error = `${rawCode}: ${(err as Error).message}`;
        }
        resolve({
          exit_code,
          stdout: out,
          stderr: errOut,
          timed_out: killed || signal === "SIGTERM" || signal === "SIGKILL",
          spawn_error,
        });
      },
    );
  });
}

function trimStderr(s: string, limit = 512): string | undefined {
  const trimmed = s.trim();
  if (!trimmed) return undefined;
  return trimmed.length > limit ? trimmed.slice(0, limit) + "…" : trimmed;
}

function truncate(
  s: string,
  n: number,
): { value: string; truncated: boolean } {
  if (s.length <= n) return { value: s, truncated: false };
  return {
    value: s.slice(0, n) + `\n… [truncated ${s.length - n} bytes]`,
    truncated: true,
  };
}

async function pool<T, R>(
  items: T[],
  n: number,
  work: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  const workerCount = Math.max(1, Math.min(n, items.length));
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await work(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}

export async function sshCheckOne(
  s: Server,
  opts: SshCheckOptions = {},
): Promise<SshCheckResult> {
  const connectTimeoutSec = opts.connect_timeout_sec ?? 5;
  const hardTimeoutMs = opts.hard_timeout_ms ?? 15_000;
  const { target, argv } = buildSshArgv(s, connectTimeoutSec, opts.extra_ssh_options);
  // No-op remote command — exits 0 immediately if auth succeeds.
  argv.push("true");
  const start = Date.now();
  const r = await runSsh(argv, hardTimeoutMs, 64 * 1024);
  const duration_ms = Date.now() - start;
  if (r.spawn_error) {
    return {
      name: s.name,
      target,
      outcome: "unknown",
      exit_code: null,
      duration_ms,
      message: `ssh failed to spawn: ${r.spawn_error}`,
    };
  }
  if (r.exit_code === 0 && !r.timed_out) {
    return {
      name: s.name,
      target,
      outcome: "ok",
      exit_code: 0,
      duration_ms,
      message: "reachable + auth ok",
    };
  }
  const outcome = classifySshFailure(r.exit_code, r.stderr, r.timed_out);
  const firstStderrLine = r.stderr
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.length > 0) ?? "";
  return {
    name: s.name,
    target,
    outcome,
    exit_code: r.exit_code,
    duration_ms,
    message: describeOutcome(outcome, firstStderrLine),
    stderr: trimStderr(r.stderr),
  };
}

export async function sshCheckMany(
  servers: Server[],
  opts: SshCheckOptions = {},
): Promise<SshCheckResult[]> {
  const parallel = opts.parallel ?? 8;
  return pool(servers, parallel, (s) => sshCheckOne(s, opts));
}

export async function execOnOne(
  s: Server,
  command: string,
  opts: ExecOnOptions = {},
): Promise<ExecOnResult> {
  const connectTimeoutSec = opts.connect_timeout_sec ?? 5;
  const hardTimeoutMs = opts.hard_timeout_ms ?? 30_000;
  const maxBytes = opts.max_output_bytes ?? 4096;
  const { target, argv } = buildSshArgv(s, connectTimeoutSec, opts.extra_ssh_options);
  // Pass the command as a single positional arg. ssh forwards it to the
  // remote login shell, so users get normal shell expansion / quoting.
  argv.push(command);
  const start = Date.now();
  const r = await runSsh(argv, hardTimeoutMs, maxBytes);
  const duration_ms = Date.now() - start;
  const out = truncate(r.stdout, maxBytes);
  const err = truncate(r.stderr, maxBytes);
  return {
    name: s.name,
    target,
    exit_code: r.exit_code,
    ok: r.exit_code === 0 && !r.timed_out && !r.spawn_error,
    duration_ms,
    stdout: out.value,
    stderr: err.value,
    stdout_truncated: out.truncated,
    stderr_truncated: err.truncated,
    timed_out: r.timed_out,
    error: r.spawn_error,
  };
}

export async function execOn(
  servers: Server[],
  command: string,
  opts: ExecOnOptions = {},
): Promise<ExecOnResult[]> {
  const parallel = opts.parallel ?? 4;
  return pool(servers, parallel, (s) => execOnOne(s, command, opts));
}

/**
 * Whether the host process is permitted to run `exec_on`. This is a hard
 * opt-in because exec_on is qualitatively different from the rest of the
 * server (read-only-ish or local-only) — it lets the agent run arbitrary
 * commands on every host in a group. Users should turn it on consciously.
 */
export function execEnabled(): boolean {
  const v = process.env.SERVER_INVENTORY_ALLOW_EXEC;
  if (!v) return false;
  const lower = v.toLowerCase();
  return lower === "1" || lower === "true" || lower === "yes" || lower === "on";
}
