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
session, performs one operation, and locks again. `geheim run` also displays a
GUI approval containing the credential names and command before authentication.

No master password or `BW_SESSION` is persisted. Secret values are not placed
in argv, files, the caller environment, or wrapper output.

## Local layout

- Configuration: `~/.config/geheim/config.toml`
- Isolated Bitwarden state: `~/.local/share/geheim/bw-data/`
- Pinned CLI: `~/.local/lib/geheim/bw-2026.4.2/bw`
- Runner: `~/.local/lib/geheim/app/geheim`
- Command: `~/.local/bin/geheim`

The dedicated Vaultwarden server is fixed to
`https://vaultwarden.example.com/`.

The installed CLI is the official x86-64 Linux archive from the Bitwarden
`cli-v2026.4.2` GitHub release. Its pinned SHA-256 digest is
`431dbe784cc7de217cb3a826993eac451aa2fbaf336538c0ff6602c1ac884c91`.

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
network interfaces. Inside that namespace, the Vaultwarden hostname resolves
only to a loopback relay. The relay has one hard-coded destination,
`vaultwarden.example.com:443`, and reaches it through the local Tailscale
daemon's Unix socket using `tailscale nc`. No DNS or general IP connectivity is
available to `bw`. This isolation does not wrap or alter the command launched
by `geheim run`.
