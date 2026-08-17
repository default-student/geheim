# geheim

`geheim` is a local, execution-only Vaultwarden credential runner for Codex.
It lets an agent discover safe item names and inject selected login passwords
into a child process environment without printing, storing, or exposing the
secret value through the wrapper.

```bash
geheim list
geheim search gitlab
geheim run -e GITLAB_TOKEN="GitLab API" -- glab api /projects
```

Each vault operation locks the isolated Bitwarden CLI state, asks for the
master password through pinentry, unlocks one temporary session, performs one
operation, and locks again. For `geheim run`, the GUI prompt also shows the
credential names and command that are being approved.

No master password or `BW_SESSION` is persisted. Secret values are not placed
in argv, files, the caller environment, or wrapper output.

## Requirements

`geheim` currently targets x86-64 Linux.

Required commands:

- `bwrap`
- `curl`
- `python3`
- `sha256sum`
- `tailscale`
- `unzip`
- `pinentry-gnome3` or `pinentry`

On Debian or Ubuntu, most dependencies can be installed with:

```bash
sudo apt install bubblewrap curl python3 unzip pinentry-gnome3
```

Install and authenticate Tailscale separately. Before setup, choose the
Vaultwarden URL you will pass to `geheim setup --url`; in the examples below
that URL is `https://vaultwarden.example.com/`.

Make sure that same hostname is reachable through Tailscale:

```bash
tailscale nc vaultwarden.example.com 443
```

The configured Vaultwarden URL must use HTTPS on port 443.

If your system uses non-standard command paths, set `GEHEIM_PINENTRY` or
`GEHEIM_TAILSCALE` before setup or execution.

## Install

From the repository root, run:

```bash
scripts/install.sh
```

The installer downloads the pinned official Bitwarden CLI Linux archive,
verifies its SHA-256 digest, and installs:

- Configuration: `~/.config/geheim/config.toml`
- Isolated Bitwarden state: `~/.local/share/geheim/bw-data/`
- Pinned CLI: `~/.local/lib/geheim/bw-2026.7.0/bw`
- Runner: `~/.local/lib/geheim/app/geheim`
- Command: `~/.local/bin/geheim`

Add `~/.local/bin` to `PATH` if your shell does not already include it:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Setup

Configure the dedicated Vaultwarden account explicitly:

```bash
geheim setup --email USER@example.com --url https://vaultwarden.example.com/
```

For an existing configuration, changing the account or server requires
`--replace`:

```bash
geheim setup --email USER@example.com --replace --url https://vaultwarden.example.com/
```

The selected hostname becomes the only network destination available to the
secret-retrieval component.

## Usage

List accessible item names:

```bash
geheim list
```

Search by name:

```bash
geheim search gitlab
```

Run a command with one credential injected into the child environment:

```bash
geheim run -e GITLAB_TOKEN="GitLab API" -- glab api /projects
```

Resolve multiple credentials in one temporary session:

```bash
geheim run \
  -e DB_USER="Development DB Username" \
  -e DB_PASSWORD="Development DB Password" \
  -- ./migration
```

The right side of each mapping is an exact accessible item name or UUID. The
secret value is the item's Bitwarden login password. Names must be unique; use
the UUID when duplicate names exist.

Use `--timeout SECONDS` to terminate a long-running child process. A timeout
returns status `124`.

## Network Isolation

Each `bw` process runs in a Bubblewrap user and network namespace with no
general network access. Inside that namespace, the configured Vaultwarden
hostname resolves only to a loopback relay. The relay connects only to the
configured Vaultwarden hostname on port 443 through `tailscale nc`.

This means Tailscale is currently part of the supported transport. The command
launched by `geheim run` is not wrapped or network-restricted by `geheim`.

## Deliberate Updates

The Bitwarden CLI version, official release URL, and SHA-256 digest are fixed
in `scripts/install.sh` and `geheim.py`. To update:

1. Choose an official Bitwarden CLI release.
2. Download the Linux archive and verify its SHA-256 digest.
3. Update the version constants and README.
4. Run the tests.
5. Run `scripts/install.sh`.

The runner never updates `bw` automatically.

## Codex Plugin

This repository also contains a Codex plugin package. The plugin manifest is at
`.codex-plugin/plugin.json` and bundles the `geheim-credentials` skill from
`skills/geheim-credentials/`.

Use the plugin when you want Codex to follow the safe local credential workflow
while running commands. The skill is guidance-only; the actual command-line
tool remains `geheim`.

## Security Boundary

The wrapper prevents accidental disclosure through its own interface, but it
cannot make a secret unknowable to the approved child program. The child needs
the value in its environment to use it. A malicious or careless child can
print, copy, or transmit that value.

Processes running as the same Unix user can generally inspect one another with
`/proc`, debuggers, or tracing unless the host adds a separate OS identity and
broker. This implementation does not claim protection from a malicious
same-user process.
