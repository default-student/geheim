#!/usr/bin/env python3
"""Atomically migrate geheim's non-secret pinned bw configuration."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("old_version")
    parser.add_argument("new_version")
    args = parser.parse_args()
    path = Path.home() / ".config" / "geheim" / "config.toml"
    content = path.read_text(encoding="utf-8")
    old_version_line = f'bw_version = "{args.old_version}"'
    new_version_line = f'bw_version = "{args.new_version}"'
    old_path = f"/bw-{args.old_version}/bw"
    new_path = f"/bw-{args.new_version}/bw"
    if new_version_line in content and new_path in content:
        return 0
    if content.count(old_version_line) != 1 or content.count(old_path) != 1:
        print("migrate_config.py: configuration does not match the expected old pin", file=sys.stderr)
        return 1
    updated = content.replace(old_version_line, new_version_line).replace(old_path, new_path)
    temporary = path.with_name("config.toml.geheim-upgrade")
    try:
        temporary.write_text(updated, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
