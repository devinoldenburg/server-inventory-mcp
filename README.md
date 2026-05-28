# server-inventory-mcp

An MCP server that lets an agent answer requests like **"run a security audit
on every logicplanes server"** without you having to tell it where the
servers are, how to log in, which key to use, or what the sudo password is.

It holds two things:

1. **A grouped, tagged inventory of SSH hosts** (hostname / user / port /
   identity\_file / jump\_host, or just an `ssh_alias` that resolves via
   `~/.ssh/config`).
2. **An encrypted secrets store** for passwords, sudo passwords, key
   passphrases, db credentials, API tokens — anything the agent needs
   to retrieve right before a call that consumes a credential.

Everything writable lives in your `~/.config/server-inventory/` directory:

```file-tree
[
  { "name": "~/.config/server-inventory", "type": "folder", "children": [
    { "name": "servers.json",  "hint": "inventory (no secrets, 0600)" },
    { "name": "secrets.enc",   "hint": "AES-256-GCM blob, master key in your macOS Keychain" },
    { "name": "audit.log",     "hint": "append-only JSON-lines, every mutation" }
  ]}
]
```

Use the `paths_report` tool (or `server-inv paths`) to get every file
location, including resolved identity\_file paths and ssh\_aliases that
don't resolve in your `~/.ssh/config`.

[![ci](https://github.com/devinoldenburg/server-inventory-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/devinoldenburg/server-inventory-mcp/actions/workflows/ci.yml)

## Why

Without an inventory, an agent told to "audit all our production servers"
has to ask you which servers count, which user to connect as, which key
to use, what password / sudo password to type, every time. With this MCP
server installed it can:

1. Call `list_groups` → see groups like `logicplanes` or `production`.
2. Call `ssh_target_for { group: "logicplanes" }` → get a ready-to-run
   `ssh ...` command for every member.
3. Call `get_server { name }` → see which secrets are available
   (`secrets.keys: ["password", "sudo_password"]`).
4. Call `get_secret` immediately before the command that needs it, pipe
   the value in, never write it to disk.
5. Run the audit, aggregate the results.

You never have to dictate where things live.

### Agent-friendly defaults (because agents make mistakes)

This server is designed to be safe for an LLM agent to drive. The mistakes
LLMs actually make in the wild are inlined into the tool surface so the agent
sees the warning at the moment of the call, not in a README it might not have
been given:

| Mistake the tool guards against | How |
|--------------------------------|------|
| Calling `add_server` twice on a retry | Hard error on duplicate name, suggesting `update_server` in the error body. |
| Confusing `delete_secret` (one key) with `remove_server` (whole entry + cascaded secrets) | Both descriptions cross-reference each other with "Mistakes to avoid:" callouts. |
| Echoing a `get_secret` value back to the user | `get_secret` description explicitly forbids it; instructions block repeats it. |
| Inlining a secret on a command line | Both `get_secret` and `exec_on` warn against this and tell the agent to pipe via stdin. |
| Firing `exec_on` across a wide group without checking | `exec_on` defaults to `dry_run: true` — first call returns reachability + the plan, second call (with `dry_run: false`) actually runs. |
| Rebuilding ssh commands from `host`/`user`/`port` | `ssh_target_for` returns a ready-to-run command string; description tells the agent to use it verbatim. |
| Proceeding past `isError: true` | The MCP `instructions` block explicitly says to treat `isError` results as not having happened. |
| Reusing stale `list_servers` output across mutations | Instructions block says re-read after every CRUD call. |

The MCP server's `instructions` block (delivered to the client during the
handshake) lays out the intended flow and an explicit "agents make mistakes —
here are the ones we've seen" section. Tool descriptions repeat the warnings
inline so they survive context compression.

### Going one step further: `ssh_check` and `exec_on`

The inventory tells the agent *where* to connect. Two further tools let it
actually act:

- **`ssh_check`** — non-interactive reachability probe. Pass a name / group
  / tag (or omit all three to probe the whole inventory) and get back a
  classified outcome per host: `ok` / `auth_failed` / `dns_failure` /
  `refused` / `timeout` / `host_key_mismatch` / `unreachable` / `unknown`.
  Bounded parallelism. Use this before kicking off a long audit so dead
  hosts and auth problems surface in seconds, not minutes.

- **`exec_on`** — run a single non-interactive command across a group and
  collect `{exit_code, stdout, stderr, duration_ms}` per host. **Strictly
  opt-in**: refuses unless `SERVER_INVENTORY_ALLOW_EXEC=1` is set in the
  MCP server's environment. Output is truncated per host (default 4 KB
  each). The audit log records the server name and exit code only —
  never the command body, never the output (both can contain credentials).

## Install

Requires Node.js 20+.

```bash
git clone https://github.com/devinoldenburg/server-inventory-mcp.git
cd server-inventory-mcp
npm install
npm run build
```

Two binaries are produced:

| Binary | Purpose |
|--------|---------|
| `dist/index.js` | The stdio MCP entry point. Wire this into your MCP client. |
| `dist/cli.js`   | A `server-inv` CLI that exposes every tool from your shell. |

## Register with an MCP client

### Codeplane (this is what was set up locally for you)

Add to `codeplane.jsonc`:

```jsonc
{
  "mcp": {
    "server-inventory": {
      "type": "local",
      "command": [
        "/opt/homebrew/bin/node",
        "/absolute/path/to/server-inventory-mcp/dist/index.js"
      ],
      "environment": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
      },
      "enabled": true,
      "timeout": 10000
    }
  }
}
```

### Claude Desktop / Cursor / anything else

The launch command is `node dist/index.js`. Pass `SERVER_INVENTORY_PATH`,
`SERVER_INVENTORY_SECRETS_PATH`, `SERVER_INVENTORY_AUDIT_LOG`, and/or
`SERVER_INVENTORY_PASSPHRASE` in the environment block to override the
defaults below.

## File locations

| File | Default | Override |
|------|---------|----------|
| Inventory       | `~/.config/server-inventory/servers.json` | `SERVER_INVENTORY_PATH` |
| Secrets         | `~/.config/server-inventory/secrets.enc`  | `SERVER_INVENTORY_SECRETS_PATH` |
| Audit log       | `~/.config/server-inventory/audit.log`    | `SERVER_INVENTORY_AUDIT_LOG` |
| Master key      | macOS Keychain (`security`) on darwin, otherwise derived from `SERVER_INVENTORY_PASSPHRASE` via scrypt | — |
| Identity files  | wherever you keep them in `~/.ssh/` — the inventory references them by absolute or `~/` path | — |
| SSH config      | `~/.ssh/config` — owned entirely by you, never modified by this server | — |
| `exec_on` gate  | off by default; set `SERVER_INVENTORY_ALLOW_EXEC=1` in the MCP server's environment to enable arbitrary remote command execution. Off elsewhere. | `SERVER_INVENTORY_ALLOW_EXEC` |

All files except `~/.ssh/config` are created with mode `0600`.

## How secrets are stored

```
┌──────────────────────────────────────────────────────────────────┐
│  agent: set_secret({ server: "lp-web-1", key: "password", ... })│
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────┐
   │  read existing secrets.enc (if any), decrypt     │
   │  with AES-256-GCM, AAD = "server-inventory-mcp:v1"│
   └──────────────────────────────────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────┐
   │  modify the in-memory map                         │
   │  { "lp-web-1": {                                  │
   │     "password": {                                 │
   │        "value": "...",                            │
   │        "created_at": "...",                       │
   │        "updated_at": "...",                       │
   │        "expires_at": "..."  (optional)            │
   │  }}}                                              │
   └──────────────────────────────────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────┐
   │  encrypt with a fresh 96-bit IV, write to .tmp,   │
   │  rename atomically to secrets.enc                 │
   └──────────────────────────────────────────────────┘
                              │
                              ▼
                       master key from
                  ┌─────────────────────────┐
                  │  macOS Keychain         │  (default on darwin —
                  │  service:                │   `-A` flag so reads
                  │   "server-inventory-mcp" │   don't prompt after
                  │  account: "master-key"   │   first add)
                  └─────────────────────────┘
                              OR
                  ┌─────────────────────────┐
                  │  scrypt-derived from     │  (cross-platform —
                  │  $SERVER_INVENTORY_      │   set the env var in
                  │   PASSPHRASE             │   your client config)
                  └─────────────────────────┘
```

The audit log records the action and the key name, never the value. If
you grep `audit.log` for a secret string, you'll never find it.

## Tools

| Tool | What it does |
|------|---------------|
| `inventory_info` | Where the inventory + secrets + audit log live; counts. |
| `paths_report` | Detailed report of every file location, including resolved identity_files (with chmod warnings) and ssh_aliases (with whether ~/.ssh/config defines them). |
| `validate_inventory` | Sanity-check every server: identity files exist, ssh_aliases resolve, every entry is reachable. |
| `list_servers` | Filter by group / tag / environment / role / free-text search. |
| `get_server` | Full record + ssh command + which secret keys are available. |
| `list_groups` | Every distinct group with member names. |
| `list_tags` | Every distinct tag with usage counts. |
| `ssh_target_for` | Resolve a name OR group OR tag to ssh commands. |
| `add_server` / `update_server` / `remove_server` | CRUD. `remove_server` cascades to delete secrets; `update_server` with `rename_to` migrates them. |
| `secrets_info` | Backend + master-key provider + secrets file path. |
| `set_secret` | Encrypt + store one value. Accepts `expires_at` (ISO) or `expires_in` (`30d`, `12h`, `2w`); preserves `created_at` across updates. Returns metadata, never the value. |
| `get_secret` | Decrypt + return one value. Call this right before the command that needs it. |
| `list_secrets` | Keys for one server **with metadata** (`created_at`, `updated_at`, optional `expires_at`, `expired`). Values are never returned. |
| `list_all_secrets` | Every server's keys with metadata + an `expired_count`. |
| `delete_secret` | Remove one key. |
| `audit_tail` | Last N entries from the audit log. |
| `ssh_check` | Probe reachability per host (`ssh -o BatchMode=yes <target> true`) with structured outcomes: `ok` / `auth_failed` / `dns_failure` / `refused` / `timeout` / `host_key_mismatch` / `unreachable` / `unknown`. Bounded parallelism, ConnectTimeout, hard kill timer. |
| `exec_on` | Run a non-interactive command across name / group / tag and return per-host `{exit_code, stdout, stderr, duration_ms}`. **Opt-in**: refuses unless `SERVER_INVENTORY_ALLOW_EXEC=1`. **Defaults to `dry_run: true`** — first call returns reachability + the plan; pass `dry_run: false` to actually run. Output truncated; audit log records server + exit code only. |

## The CLI

```bash
server-inv ls                          # list servers
server-inv get lp-web-1                # detail + ssh command + secret keys
server-inv groups                      # all groups with member names
server-inv targets --group logicplanes # ssh commands, one per line, ready to pipe

server-inv add lp-web-1 --host 10.0.0.5 --user ubuntu \
  --group logicplanes --group production --tag web --tag nginx \
  --env production --role web --desc "primary public web"

server-inv update lp-web-1 --port 2222 --tag tls
server-inv update lp-web-1 --rename-to lp-web-primary

echo -n 'hunter2' | server-inv secret set lp-web-1 password
echo -n 'tok-abc' | server-inv secret set lp-web-1 api_token --expires-in 30d
server-inv secret get lp-web-1 password   # prints value to stdout
server-inv secret ls                       # all servers' keys
server-inv secret ls lp-web-1 --meta       # keys + created_at/updated_at/expires_at
server-inv secret rm lp-web-1 password

server-inv ssh-check --group logicplanes   # probe every host, non-zero exit if any down
server-inv ssh-check --all --timeout-sec 3
SERVER_INVENTORY_ALLOW_EXEC=1 \
  server-inv exec --group logicplanes -- "uptime && uname -r"   # dry-run by default
SERVER_INVENTORY_ALLOW_EXEC=1 \
  server-inv exec --group logicplanes --run -- "uptime && uname -r"   # actually fire

server-inv paths                       # paths_report as JSON
server-inv validate                    # validate_inventory as JSON
server-inv audit --limit 20            # tail of the audit log

server-inv rm lp-web-1                 # cascades to delete secrets
```

The CLI writes to the same files as the MCP server and logs to the same
audit log (with `cli:` prefixed tool names) so an operator can tell a
manual change from an agent-driven one.

## Example: "audit all logicplanes servers"

A realistic agent flow once the inventory is populated:

```
user → agent → MCP

agent: list_groups
       ← { groups: [{ name: "logicplanes", count: 4, members: [...] }, ...] }

agent: ssh_target_for { group: "logicplanes" }
       ← { count: 4, targets: [
             { name: "lp-web-1",   command: "ssh ubuntu@10.0.0.5", ... },
             { name: "lp-db-1",    command: "ssh lp-db-1",         ... },
             { name: "lp-app-1",   command: "ssh -J ops@bastion deploy@10.0.1.20" },
             ...
         ] }

for each target:
  agent: get_server { name }
         ← { ..., secrets: { keys: ["sudo_password"], hint: "..." } }

  agent: get_secret { server, key: "sudo_password" }
         ← { value: "..." }       # used immediately, not persisted

  agent (via its own ssh tool): ssh ... 'echo "$sudo_pw" | sudo -S lynis audit system --quick'

  agent: collects findings
```

The agent never had to ask you which servers count, what credentials to
use, or where the keys live. `paths_report` would have told it everything
in one call if it ever needed to debug.

## Security model

What this server is good for:

- Personal / small-team inventory that lives on your laptop or a single
  workstation. The encrypted secrets file is unreadable without the
  master key, which never leaves your keychain (or env var).
- Replacing "credentials pasted into chat" with "credentials retrieved
  from an encrypted local store the moment the agent needs them".
- An audit trail of what was changed and when.

What it is **not**:

- A team password manager. There's no sharing, no rotation policy. Per-key
  `expires_at` is a reminder mechanism (surfaced through `list_secrets` and
  `validate_inventory`); it does NOT delete or rotate the value. Use
  1Password / Bitwarden / Vault for actual team credential management.
- An access-control system. Anything that can talk to this MCP server
  can read all the secrets. Don't expose it over the network.
- Tamper-proof. The audit log is on disk and can be deleted. If you
  need cryptographically verifiable history, ship the audit log to a
  WORM store.

## Development

```bash
npm install
npm run build     # compile TypeScript -> dist/
npm run test:unit # node --test on the unit suites
npm run smoke     # spawn the built MCP server, exercise every tool
npm test          # build + unit + smoke chained
npm run dev       # run src/index.ts directly via tsx (no build)
```

Set `SERVER_INVENTORY_TRACE=1` for stderr breadcrumbs from the lock /
load / save paths when debugging.

## License

MIT — see [LICENSE](LICENSE).
