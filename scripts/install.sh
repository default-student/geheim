#!/bin/sh
set -eu

BW_VERSION=2026.7.0
BW_SHA256=7a35145e205952f7434d2370da359543145ae0c45ba1af0fe9bdd99d40a00180
BW_URL="https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip"
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LIB_DIR="${HOME}/.local/lib/geheim"
BIN_DIR="${HOME}/.local/bin"
INSTALL_DIR="${LIB_DIR}/bw-${BW_VERSION}"
PROGRAM_DIR="${LIB_DIR}/app"
NETWORK_DIR="${LIB_DIR}/network"
BW_DATA_DIR="${HOME}/.local/share/geheim/bw-data"

for command in curl sha256sum unzip; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "install.sh: missing required command: $command" >&2
        exit 1
    fi
done

for command in bwrap python3 tailscale; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "install.sh: missing required command: $command" >&2
        exit 1
    fi
done

if ! command -v pinentry-gnome3 >/dev/null 2>&1 && ! command -v pinentry >/dev/null 2>&1; then
    echo "install.sh: missing required command: pinentry-gnome3 or pinentry" >&2
    exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

curl --fail --silent --show-error --location "$BW_URL" --output "$tmp_dir/bw.zip"
printf '%s  %s\n' "$BW_SHA256" "$tmp_dir/bw.zip" | sha256sum --check --status
mkdir -p "$INSTALL_DIR" "$PROGRAM_DIR" "$NETWORK_DIR" "$BIN_DIR" "$BW_DATA_DIR"
chmod 0700 "$BW_DATA_DIR"
unzip -q -o "$tmp_dir/bw.zip" -d "$INSTALL_DIR"
chmod 0755 "$INSTALL_DIR/bw"
install -m 0755 "$PROJECT_DIR/geheim.py" "$PROGRAM_DIR/geheim"
install -m 0755 "$PROJECT_DIR/network/network_runner.py" "$NETWORK_DIR/network_runner.py"
install -m 0644 "$PROJECT_DIR/network/hosts" "$NETWORK_DIR/hosts"
if [ -f "${HOME}/.config/geheim/config.toml" ]; then
    python3 "$PROJECT_DIR/scripts/migrate_config.py" 2026.4.2 "$BW_VERSION"
fi
ln -sfn "$PROGRAM_DIR/geheim" "$BIN_DIR/geheim"

installed_version=$(BITWARDENCLI_APPDATA_DIR="$BW_DATA_DIR" "$INSTALL_DIR/bw" --version)
if [ "$installed_version" != "$BW_VERSION" ]; then
    echo "install.sh: expected bw $BW_VERSION, got $installed_version" >&2
    exit 1
fi
echo "Installed geheim commands and pinned bw ${BW_VERSION}."
