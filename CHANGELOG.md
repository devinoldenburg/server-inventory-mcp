# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] — 2026-05-28

### Added

- **Agent-friendly defaults** across the tool surface. The MCP
  `instructions` block now ships an explicit "agents make mistakes —
  here are the ones we've seen" section listing the real failure modes
  (double create, secret echo, secret on command line, delete_secret /
  remove_server confusion, building ssh commands from scratch, wide
  exec_on without probing, ignoring `isError`, stale `list_servers`
  cache).
- **"Mistakes to avoid:" callouts** inlined into the description of
  every high-misuse tool (`add_server`, `update_server`, `remove_server`,
  `set_secret`, `get_secret`, `delete_secret`, `ssh_target_for`,
  `ssh_check`, `exec_on`) so an agent sees the warning at tool-listing
  time — survives context compression that might drop the global
  instructions.

### Changed

- **`exec_on` now defaults to `dry_run: true`.** The first call returns
  reachability + the planned target list + the would-be command, and
  does NOT execute. Pass `dry_run: false` (with the same name/group/tag)
  to actually fire. The CLI `server-inv exec` mirrors this: dry-run by
  default, `--run` to execute. Both still require
  `SERVER_INVENTORY_ALLOW_EXEC=1` regardless of `dry_run` — the env
  gate controls whether the tool functions at all.
- **Error messages now suggest the right next call.** "Server X not
  found" now appends "Call list_servers …"; "already exists" suggests
  `update_server`; "Provide exactly one of name/group/tag" points at
  `list_groups` / `list_tags`; rename collisions suggest checking
  `list_servers` first.
- Audit log gained a separate `exec_on:dry_run` tool name so a future
  audit_tail consumer can tell plans apart from real executions.

## [0.4.0] — 2026-05-28

### Added

- **`ssh_check` tool** — non-interactive reachability probe across one or
  many servers (`ssh -o BatchMode=yes <target> true`). Structured outcome
  per host: `ok` / `auth_failed` / `dns_failure` / `refused` / `timeout` /
  `host_key_mismatch` / `unreachable` / `unknown`. Bounded parallelism,
  configurable ConnectTimeout, hard kill timer.
- **`exec_on` tool** — run a non-interactive command across name / group /
  tag and return per-host `{exit_code, stdout, stderr, duration_ms}`.
  Strictly opt-in: refuses unless `SERVER_INVENTORY_ALLOW_EXEC=1`. Output
  truncated per host; audit log records server + exit code only.
- **`server-inv ssh-check`** and **`server-inv exec`** CLI subcommands
  mirror the new MCP tools. Both exit non-zero if any host fails so they
  drop straight into shell pipelines / CI.
- **Per-secret metadata** — every stored secret now carries
  `created_at`, `updated_at`, and an optional `expires_at`. `set_secret`
  accepts `expires_at` (ISO) or `expires_in` (`30d` / `12h` / `2w`); CLI
  accepts the same via `--expires-at` / `--expires-in`. `list_secrets` /
  `list_all_secrets` return per-key metadata and an `expired_count`.
- **Expired-credential detection** in `validate_inventory`: secrets past
  their `expires_at` are surfaced as warnings, alongside orphan secrets
  (rows in the secrets store with no matching inventory entry).
- **Secrets-file schema versioning + migration runner**. The envelope
  now carries `data_version`; legacy v1 files (plain-string values, no
  metadata) are migrated transparently on read and persisted on the next
  write. The migration framework is set up for future v2→v3 steps.

### Changed

- **`SecretsStore.rename(old, new)`** — server renames now move every
  secret key in a single read/decrypt/encrypt/write cycle instead of
  one round-trip per key. Both MCP `update_server` and CLI `update
  --rename-to` use it.
- `SecretsStore.set` accepts an `options` arg (`{ expires_at }`); the
  3-arg signature still works.
- `list_secrets` MCP response now includes an `entries: SecretMeta[]`
  field alongside the existing `keys: string[]`.
- `list_all_secrets` MCP response now includes `by_server_meta` and
  `expired_count` alongside the existing `by_server`.
- `secrets_info` now reports `data_version`.
- CLI `secret ls --meta` flag dumps the metadata view.
- CLI arg parser now honours `--` as the end-of-flags sentinel so
  `server-inv exec --group g -- 'cmd --with-its-own-flags'` does what
  you expect.

### Security

- `exec_on` (and CLI `exec`) require a deliberate opt-in
  (`SERVER_INVENTORY_ALLOW_EXEC=1`); the tool registers either way so an
  agent can discover its existence, but invocation returns a clear
  refusal message until enabled.
- `exec_on` audit entries record only `{server, ok, exit_code,
  duration_ms, timed_out}` — never the command text, never the output —
  because both can contain operator credentials or PII.

### Tests

- **34 unit tests** (up from 21) covering: v1→v2 migration, metadata
  round-trip, expiry detection, batched rename single-write, the full
  `classifySshFailure` truth table, `parseExpiresIn`.
- **56 smoke checks** (up from 46): the new tools, metadata visibility,
  expired-secret detection in `validate_inventory`, ssh_check against
  RFC 2606 `.invalid`, exec_on gating refusal.

## [0.3.0] — 2026-05-26

### Added

- **Encrypted secrets store** anchored by the macOS Keychain (or a
  passphrase env var on other platforms). Per-server key/value secrets
  via `set_secret`, `get_secret`, `list_secrets`, `list_all_secrets`,
  `delete_secret`, and a `secrets_info` introspection tool.
- **Cascade behaviour** on inventory mutations: `remove_server` deletes
  the server's secrets; `update_server` with `rename_to` migrates them
  to the new name.
- **`paths_report` tool** that returns every file location the server
  cares about (inventory, secrets, audit log, `~/.ssh/config`, every
  referenced identity file with chmod warnings, every ssh_alias with
  whether it resolves in ssh config) plus a per-server breakdown.
- **`validate_inventory` tool** flagging missing identity files,
  world-readable keys, undefined ssh_aliases, and unreachable entries.
- **Audit log** (`~/.config/server-inventory/audit.log`, JSON-lines)
  for every mutation. Secret values are never recorded. New
  `audit_tail` tool to read the last N entries.
- **`server-inv` CLI** binary exposing the same surface from the shell.
  `secret set` reads the value from stdin so passwords never appear
  in shell history.
- **CI matrix** expanded to ubuntu-latest + macos-latest on node 20 and 22.
- **21 unit tests** under `tests/` covering schema, store, secrets,
  paths, and the SSH command builder.

### Changed

- `get_server` now returns `secrets.keys` and a usage hint.
- `list_servers` now includes `secret_count` per row.
- `inventory_info` now also reports `secrets_path` and the global counts.
- MCP `instructions` block now teaches the safe secret-handling pattern.

### Security

- Secrets file uses AES-256-GCM with AAD bound to a literal version
  string so the key cannot be tricked into reading ciphertext from a
  different application.
- macOS Keychain master-key item is created with `-A` so reads after
  the initial `add-generic-password` don't prompt.
- Files written by this server are mode `0600`.
- Audit log never contains secret values, only key names.

## [0.1.0] — 2026-05-26

### Added

- Initial release. MCP stdio server with 9 tools:
  `inventory_info`, `list_servers`, `get_server`, `list_groups`,
  `list_tags`, `ssh_target_for`, `add_server`, `update_server`,
  `remove_server`.
- JSON inventory file with atomic writes and an in-process serialisation
  queue.
- Smoke-test script and GitHub Actions CI on node 20 + 22.
