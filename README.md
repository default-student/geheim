# geheim

`geheim` is a local, execution-only Vaultwarden credential runner for Codex.
It exposes only safe item names during discovery and injects selected login
passwords directly into a child process environment.

```bash
geheim list
geheim search gitlab
geheim run -e GITLAB_TOKEN="GitLab API" -- glab api /projects
```

Every vault operation begins by locking the dedicated Bitwarden CLI state,
asks for the master password in `pinentry-gnome3`, unlocks one temporary
session, performs one operation, and locks again. For `geheim run`, the single
GUI password prompt also displays the credential names and command; submitting
the password approves that one execution.

No master password or `BW_SESSION` is persisted. Secret values are not placed
in argv, files, the caller environment, or wrapper output.

## Local layout

- Configuration: `~/.config/geheim/config.toml`
- Isolated Bitwarden state: `~/.local/share/geheim/bw-data/`
- Pinned CLI: `~/.local/lib/geheim/bw-2026.7.0/bw`
- Runner: `~/.local/lib/geheim/app/geheim`
- Command: `~/.local/bin/geheim`

## Requirements

This installer targets x86-64 Linux. It expects `curl`, `sha256sum`, `unzip`,
`bwrap`, `python3`, `tailscale`, and either `pinentry-gnome3` or `pinentry`.
The configured Vaultwarden host must be reachable through `tailscale nc` on
port 443.

Configure the dedicated Vaultwarden server explicitly during setup:

```bash
geheim setup --email USER --url https://vaultwarden.example.com/
```

For an existing configuration, changing the server requires `--replace`:

```bash
geheim setup --email USER --replace --url https://vaultwarden.example.com/
```

`--url` requires HTTPS and port 443. The selected hostname becomes the sole
network destination allowed to the secret-retrieval component.

The installed CLI is the official x86-64 Linux archive from the Bitwarden
`cli-v2026.7.0` GitHub release. Its pinned SHA-256 digest is
`7a35145e205952f7434d2370da359543145ae0c45ba1af0fe9bdd99d40a00180`.
The previous `bw-2026.4.2` installation is retained locally for deliberate
rollback until the optimized serve lifecycle passes acceptance testing.

## Credential format

The right side of a mapping is an exact accessible item name or UUID. The
secret value is the item's Bitwarden login password. Names must be unique;
use the UUID when duplicate names exist.

Multiple credentials are resolved in one temporary session:

```bash
geheim run \
  -e DB_USER="Development DB Username" \
  -e DB_PASSWORD="Development DB Password" \
  -- ./migration
```

An optional `--timeout SECONDS` terminates a long-running child and returns
status 124.

## Deliberate updates

The version, official release URL, and SHA-256 digest are fixed in
`scripts/install.sh` and `geheim.py`. To update, choose an official Bitwarden
CLI release, download its Linux archive, verify and record its SHA-256 digest,
update both version constants and the documentation, run the tests, and then
run `scripts/install.sh`. The runner never updates `bw` automatically.

## Security boundary

The wrapper prevents accidental disclosure through its own interface, but it
cannot make a secret unknowable to the approved child program. The child needs
the value in its environment to use it. A malicious or carelessly invoked
child can print, copy, or transmit that value. The GUI approval and persistent
Codex instruction are therefore part of the boundary.

Likewise, processes running as the same Unix user can generally inspect one
another with `/proc`, debuggers, or tracing unless the host adds a separate OS
identity and broker. This implementation does not claim protection from a
malicious same-user Codex process.

Each `bw` process runs in a Bubblewrap user and network namespace with no
network interfaces. Inside that namespace, the configured Vaultwarden hostname
resolves only to a loopback relay. The relay has one configured destination,
the configured Vaultwarden hostname on port 443, and reaches it through the
local Tailscale daemon's Unix socket using `tailscale nc`. No DNS or general IP
connectivity is available to `bw`. This isolation does not wrap or alter the
command launched by `geheim run`.
