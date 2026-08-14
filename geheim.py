#!/usr/bin/env python3
"""Local, execution-only Bitwarden/Vaultwarden credential runner."""

from __future__ import annotations

import argparse
import difflib
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from typing import NoReturn, Sequence


SERVER = "https://vaultwarden.example.com/"
BW_VERSION = "2026.4.2"
DEFAULT_CONFIG = Path.home() / ".config" / "geheim" / "config.toml"
DEFAULT_BW_DATA = Path.home() / ".local" / "share" / "geheim" / "bw-data"
DEFAULT_BW = Path.home() / ".local" / "lib" / "geheim" / f"bw-{BW_VERSION}" / "bw"
DEFAULT_PINENTRY = Path("/usr/bin/pinentry-gnome3")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class GeheimError(Exception):
    pass


class AuthenticationCancelled(GeheimError):
    pass


@dataclass(frozen=True)
class Config:
    email: str
    server: str
    bw_path: Path
    bw_data_dir: Path
    pinentry_path: Path
    bw_version: str
    network_enforcement: str = "none"
    network_allow: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG) -> "Config":
        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except FileNotFoundError as exc:
            raise GeheimError(f'geheim is not configured. Run "geheim setup" first. ({path})') from exc
        required = ("email", "server", "bw_path", "bw_data_dir", "pinentry_path", "bw_version")
        missing = [key for key in required if not raw.get(key)]
        if missing:
            raise GeheimError(f"Invalid geheim configuration: missing {', '.join(missing)}")
        cfg = cls(
            email=str(raw["email"]),
            server=str(raw["server"]),
            bw_path=Path(raw["bw_path"]),
            bw_data_dir=Path(raw["bw_data_dir"]),
            pinentry_path=Path(raw["pinentry_path"]),
            bw_version=str(raw["bw_version"]),
            network_enforcement=str(raw.get("network_enforcement", "none")),
            network_allow=tuple(str(item) for item in raw.get("network_allow", [])),
        )
        if cfg.server.rstrip("/") != SERVER.rstrip("/"):
            raise GeheimError(f"Refusing unexpected server in configuration: {cfg.server}")
        if cfg.bw_version != BW_VERSION:
            raise GeheimError(
                f"Configured bw version is {cfg.bw_version}, but this geheim release requires {BW_VERSION}."
            )
        return cfg


def write_config(config: Config, path: Path = DEFAULT_CONFIG) -> None:
    def quote(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.bw_data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    os.chmod(config.bw_data_dir, 0o700)
    content = "\n".join(
        [
            f"email = {quote(config.email)}",
            f"server = {quote(config.server)}",
            f"bw_path = {quote(str(config.bw_path))}",
            f"bw_data_dir = {quote(str(config.bw_data_dir))}",
            f"pinentry_path = {quote(str(config.pinentry_path))}",
            f"bw_version = {quote(config.bw_version)}",
            f"network_enforcement = {quote(config.network_enforcement)}",
            "network_allow = [" + ", ".join(quote(item) for item in config.network_allow) + "]",
            "",
        ]
    )
    fd, temporary = tempfile.mkstemp(prefix="config.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _pinentry_escape(value: str) -> bytes:
    return value.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D").encode()


def _pinentry_unescape(value: bytes) -> bytes:
    return value.replace(b"%0A", b"\n").replace(b"%0D", b"\r").replace(b"%25", b"%")


class Pinentry:
    def __init__(self, executable: Path):
        self.executable = executable

    def _exchange(self, commands: Sequence[bytes], expect_data: bool) -> bytearray | None:
        if not self.executable.is_file():
            raise GeheimError(f"pinentry executable not found: {self.executable}")
        proc = subprocess.Popen(
            [str(self.executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        assert proc.stdin is not None and proc.stdout is not None
        data: bytearray | None = None
        try:
            greeting = proc.stdout.readline()
            if not greeting.startswith(b"OK"):
                raise GeheimError("pinentry did not start correctly")
            for command in commands:
                proc.stdin.write(command + b"\n")
                proc.stdin.flush()
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        raise GeheimError("pinentry closed unexpectedly")
                    line = line.rstrip(b"\r\n")
                    if line.startswith(b"D "):
                        data = bytearray(_pinentry_unescape(line[2:]))
                    elif line.startswith(b"OK"):
                        break
                    elif line.startswith(b"ERR"):
                        if b"cancel" in line.lower():
                            raise AuthenticationCancelled("Authentication was cancelled.")
                        raise GeheimError("pinentry rejected the request")
            if expect_data and data is None:
                raise GeheimError("pinentry returned no password")
            return data
        finally:
            try:
                proc.stdin.write(b"BYE\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def confirm_run(self, mappings: Sequence[tuple[str, str]], command: Sequence[str]) -> None:
        safe_mappings = "\n".join(f"{name} <- {item}" for name, item in mappings)
        rendered = shlex.join(command)
        description = f"Allow geheim run?\n\nCredentials:\n{safe_mappings}\n\nCommand:\n{rendered}"
        self._exchange(
            [
                b"SETTITLE geheim approval",
                b"SETDESC " + _pinentry_escape(description),
                b"SETOK Run once",
                b"SETCANCEL Cancel",
                b"CONFIRM",
            ],
            expect_data=False,
        )

    def password(self, operation: str, email: str) -> bytearray:
        description = f"Unlock the Codex Vaultwarden account for one {operation} operation.\nAccount: {email}"
        result = self._exchange(
            [
                b"SETTITLE geheim Vaultwarden authentication",
                b"SETDESC " + _pinentry_escape(description),
                b"SETPROMPT Master password:",
                b"SETOK Unlock once",
                b"SETCANCEL Cancel",
                b"GETPIN",
            ],
            expect_data=True,
        )
        assert result is not None
        return result


class Bw:
    def __init__(self, config: Config):
        self.config = config
        if not config.bw_path.is_file():
            raise GeheimError(f"Pinned bw executable not found: {config.bw_path}")

    def _base_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("BW_SESSION", None)
        env.pop("BW_PASSWORD", None)
        env["BITWARDENCLI_APPDATA_DIR"] = str(self.config.bw_data_dir)
        env["NO_COLOR"] = "1"
        return env

    def _command(self, args: Sequence[str]) -> list[str]:
        command = [str(self.config.bw_path), *args]
        if self.config.network_enforcement == "none":
            return command
        if self.config.network_enforcement != "bubblewrap-tailscale":
            raise GeheimError(f"Unknown network enforcement mode: {self.config.network_enforcement}")
        geheim_root = self.config.bw_path.parent.parent
        runner = geheim_root / "network" / "network_runner.py"
        hosts = geheim_root / "network" / "hosts"
        if not runner.is_file() or not hosts.is_file():
            raise GeheimError("geheim network-isolation support files are missing")
        return [
            "/usr/bin/bwrap",
            "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "CAP_NET_BIND_SERVICE",
            "--unshare-net", "--die-with-parent", "--new-session",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--bind", str(self.config.bw_data_dir), str(self.config.bw_data_dir),
            "--ro-bind", str(hosts), "/etc/hosts",
            "/usr/bin/python3", str(runner), *command,
        ]

    def run(
        self,
        args: Sequence[str],
        *,
        session: str | None = None,
        password: bytearray | None = None,
        check: bool = True,
        timeout: float = 60,
    ) -> subprocess.CompletedProcess[str]:
        env = self._base_env()
        if session is not None:
            env["BW_SESSION"] = session
        password_text: str | None = None
        if password is not None:
            password_text = password.decode("utf-8")
            env["GEHEIM_MASTER_PASSWORD"] = password_text
        try:
            result = subprocess.run(
                self._command(args),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        finally:
            env.pop("GEHEIM_MASTER_PASSWORD", None)
            password_text = None
        if check and result.returncode != 0:
            message = _safe_bw_error(result.stderr)
            raise GeheimError(message or f"bw command failed with exit code {result.returncode}")
        return result

    def lock(self, *, allow_unauthenticated: bool = False) -> str:
        result = self.run(["lock"], check=False, timeout=20)
        if result.returncode == 0:
            return "locked"
        if allow_unauthenticated:
            status = self.status()
            if status == "unauthenticated":
                return status
        raise GeheimError("Could not lock the Vaultwarden CLI state")

    def status(self) -> str:
        result = self.run(["status"], timeout=20)
        try:
            return str(json.loads(result.stdout)["status"])
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise GeheimError("bw returned an invalid status response") from exc

    def safe_items(self, session: str, query: str | None = None) -> list[dict[str, str]]:
        args = ["list", "items"]
        if query:
            args.extend(["--search", query])
        env = self._base_env()
        env["BW_SESSION"] = session
        bw_proc = subprocess.Popen(
            self._command(args),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert bw_proc.stdout is not None and bw_proc.stderr is not None
        sanitizer = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "__sanitize-items"],
            stdin=bw_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        bw_proc.stdout.close()
        try:
            sanitized_stdout, _ = sanitizer.communicate(timeout=60)
            bw_stderr = bw_proc.stderr.read().decode("utf-8", "replace")
            bw_returncode = bw_proc.wait(timeout=5)
        except BaseException:
            sanitizer.kill()
            bw_proc.kill()
            sanitizer.wait()
            bw_proc.wait()
            raise
        if bw_returncode != 0:
            raise GeheimError(_safe_bw_error(bw_stderr) or "Vaultwarden operation failed.")
        if sanitizer.returncode != 0:
            raise GeheimError("Could not sanitize the Bitwarden item response")
        try:
            items = json.loads(sanitized_stdout)
        except json.JSONDecodeError as exc:
            raise GeheimError("The item sanitizer returned an invalid response") from exc
        if not isinstance(items, list):
            raise GeheimError("The item sanitizer returned an invalid response")
        return items


def _safe_bw_error(stderr: str) -> str:
    lower = stderr.lower()
    if "invalid master password" in lower or "incorrect" in lower:
        return "Vaultwarden authentication was rejected."
    if "not logged in" in lower or "unauthenticated" in lower:
        return 'The Codex Vaultwarden account is not logged in. Run "geheim setup".'
    if any(marker in lower for marker in ("fetch failed", "network request failed", "econnrefused", "enotfound")):
        return "The Vaultwarden network request failed."
    if "certificate" in lower or "tls" in lower:
        return "Vaultwarden TLS verification failed."
    if "session key" in lower and ("invalid" in lower or "missing" in lower):
        return "The temporary Vaultwarden session was rejected."
    if "vault is locked" in lower:
        return "Vaultwarden reported that the vault is locked."
    if "failed to decrypt" in lower or "cannot decrypt" in lower:
        return "Vaultwarden item decryption failed."
    if "timeout" in lower or "timed out" in lower:
        return "Vaultwarden operation timed out."
    return "Vaultwarden operation failed."


class VaultOperation:
    def __init__(self, config: Config, operation: str):
        self.config = config
        self.operation = operation
        self.bw = Bw(config)
        self.pinentry = Pinentry(config.pinentry_path)
        self.session: str | None = None
        self.vault_closed = False
        self._lock_handle = None

    def __enter__(self) -> "VaultOperation":
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/geheim-{os.getuid()}")) / "geheim"
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(runtime, 0o700)
        self._lock_handle = (runtime / "operation.lock").open("a+")
        fcntl.flock(self._lock_handle, fcntl.LOCK_EX)
        try:
            self.bw.lock()
            password = self.pinentry.password(self.operation, self.config.email)
            try:
                result = self.bw.run(
                    ["unlock", "--passwordenv", "GEHEIM_MASTER_PASSWORD", "--raw"], password=password
                )
            finally:
                for index in range(len(password)):
                    password[index] = 0
            session = result.stdout.strip()
            if not session or "\n" in session:
                raise GeheimError("bw did not return a valid temporary session")
            self.session = session
            return self
        except BaseException:
            try:
                self.bw.lock()
            finally:
                fcntl.flock(self._lock_handle, fcntl.LOCK_UN)
                self._lock_handle.close()
                self._lock_handle = None
            raise

    def close_vault(self) -> None:
        if self.vault_closed:
            return
        if self.session is not None:
            self.session = None
        self.bw.lock()
        self.vault_closed = True

    def __exit__(self, exc_type, exc, traceback) -> bool:
        lock_error: GeheimError | None = None
        try:
            self.close_vault()
        except GeheimError as caught:
            lock_error = caught
        finally:
            if self._lock_handle is not None:
                fcntl.flock(self._lock_handle, fcntl.LOCK_UN)
                self._lock_handle.close()
        if lock_error is not None and exc is None:
            raise lock_error
        return False

    def sync(self) -> None:
        assert self.session is not None
        self.bw.run(["sync"], session=self.session)

    def items(self, query: str | None = None) -> list[dict]:
        assert self.session is not None
        return self.bw.safe_items(self.session, query)

    def password_for(self, item_id: str) -> str:
        assert self.session is not None
        result = self.bw.run(["get", "password", item_id], session=self.session)
        value = result.stdout.rstrip("\n")
        if not value:
            raise GeheimError("The selected credential has no login password value.")
        return value


def safe_names(items: Sequence[dict]) -> list[str]:
    return sorted({str(item.get("name", "")).strip() for item in items if str(item.get("name", "")).strip()}, key=str.casefold)


def resolve_item(items: Sequence[dict], identifier: str) -> dict | None:
    uuid_matches = [item for item in items if str(item.get("id", "")).casefold() == identifier.casefold()]
    if len(uuid_matches) == 1:
        return uuid_matches[0]
    name_matches = [item for item in items if str(item.get("name", "")) == identifier]
    if len(name_matches) > 1:
        raise GeheimError(f'More than one credential is named "{identifier}". Use its UUID instead.')
    return name_matches[0] if name_matches else None


def missing_message(identifier: str, names: Sequence[str]) -> str:
    query = re.sub(r"[^A-Za-z0-9]+", " ", identifier).strip().split(" ")[0].lower() or "credential"
    close = difflib.get_close_matches(identifier, names, n=5, cutoff=0.35)
    lines = [
        f'Credential "{identifier}" is not available.', "", "Search accessible credentials with:",
        f"    geheim search {shlex.quote(query)}", "",
        "If the credential should be available, grant the configured Codex",
        "Vaultwarden user access to the corresponding item or collection.",
    ]
    if close:
        lines.extend(["", "Possible matches:", *(f"  {name}" for name in close)])
    return "\n".join(lines)


def parse_mapping(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("secret mapping must be ENV_VAR=ITEM_NAME_OR_UUID")
    name, item = value.split("=", 1)
    if not ENV_NAME.fullmatch(name):
        raise argparse.ArgumentTypeError(f"invalid environment variable name: {name}")
    if not item:
        raise argparse.ArgumentTypeError("credential name or UUID must not be empty")
    return name, item


def command_list(config: Config, query: str | None) -> int:
    operation = "search" if query is not None else "list"
    with VaultOperation(config, operation) as vault:
        try:
            vault.sync()
        except GeheimError as exc:
            raise GeheimError(f"Credential synchronization failed: {exc}") from exc
        try:
            names = safe_names(vault.items(query))
        except GeheimError as exc:
            raise GeheimError(f"Credential discovery failed: {exc}") from exc
    for name in names:
        print(name)
    if not names:
        if query is None:
            print("No accessible credentials are available.")
        else:
            print(f'No accessible credentials matched "{query}".')
    return 0


def command_run(config: Config, mappings: Sequence[tuple[str, str]], command: Sequence[str], timeout: float | None) -> int:
    if not mappings:
        raise GeheimError("geheim run requires at least one -e ENV_VAR=ITEM mapping")
    if not command:
        raise GeheimError("geheim run requires a command after --")
    if len({name for name, _ in mappings}) != len(mappings):
        raise GeheimError("Each environment variable may be mapped only once")
    pinentry = Pinentry(config.pinentry_path)
    pinentry.confirm_run(mappings, command)
    secrets: dict[str, str] = {}
    with VaultOperation(config, "geheim run") as vault:
        vault.sync()
        all_items = vault.items()
        names = safe_names(all_items)
        resolved: list[tuple[str, dict]] = []
        for env_name, identifier in mappings:
            item = resolve_item(all_items, identifier)
            if item is None:
                raise GeheimError(missing_message(identifier, names))
            resolved.append((env_name, {"id": str(item["id"])}))
        for item in all_items:
            item.clear()
        all_items.clear()
        for env_name, item in resolved:
            secrets[env_name] = vault.password_for(item["id"])
        vault.close_vault()

        child_env = os.environ.copy()
        child_env.pop("BW_SESSION", None)
        child_env.pop("BW_PASSWORD", None)
        child_env.update(secrets)
        proc: subprocess.Popen | None = None
        old_handlers: dict[int, object] = {}

        def forward(signum, frame):
            if proc is not None and proc.poll() is None:
                proc.send_signal(signum)

        try:
            for signum in (signal.SIGTERM, signal.SIGHUP):
                old_handlers[signum] = signal.signal(signum, forward)
            proc = subprocess.Popen(list(command), env=child_env)
            try:
                return proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                print("geheim run: child command timed out", file=sys.stderr)
                return 124
        except FileNotFoundError as exc:
            raise GeheimError(f"Command not found: {command[0]}") from exc
        finally:
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
            for key in secrets:
                secrets[key] = ""
                child_env.pop(key, None)


def command_setup(email: str, replace: bool, config_path: Path) -> int:
    if config_path.exists() and not replace:
        raise GeheimError(
            f"geheim is already configured at {config_path}. Use --replace to change the dedicated account."
        )
    previous: Config | None = None
    if config_path.exists():
        previous = Config.load(config_path)
    config = Config(
        email=email,
        server=SERVER,
        bw_path=DEFAULT_BW,
        bw_data_dir=DEFAULT_BW_DATA,
        pinentry_path=DEFAULT_PINENTRY,
        bw_version=BW_VERSION,
        network_enforcement="bubblewrap-tailscale",
    )
    config.bw_data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(config.bw_data_dir, 0o700)
    bw = Bw(config)
    pinentry = Pinentry(config.pinentry_path)
    status = bw.lock(allow_unauthenticated=True)
    try:
        same_account_reset = (
            replace
            and previous is not None
            and previous.email == email
            and previous.server.rstrip("/") == SERVER.rstrip("/")
            and status == "locked"
        )
        if status != "unauthenticated" and not same_account_reset:
            if not replace:
                raise GeheimError("The isolated bw state already contains a logged-in account.")
            result = bw.run(["logout"], check=False)
            if result.returncode != 0:
                raise GeheimError("Could not log out the previously configured Vaultwarden account.")
        if not same_account_reset:
            bw.run(["config", "server", SERVER])
        password = pinentry.password("setup verification" if same_account_reset else "initial login", email)
        try:
            if same_account_reset:
                result = bw.run(
                    ["unlock", "--passwordenv", "GEHEIM_MASTER_PASSWORD", "--raw"],
                    password=password,
                )
            else:
                result = bw.run(
                    ["login", email, "--passwordenv", "GEHEIM_MASTER_PASSWORD", "--raw"],
                    password=password,
                )
        finally:
            for index in range(len(password)):
                password[index] = 0
        if not result.stdout.strip():
            raise GeheimError("bw login did not return a temporary session")
    finally:
        bw.lock(allow_unauthenticated=True)
    write_config(config, config_path)
    print(f"Configured dedicated Vaultwarden account {email}; vault status is locked.")
    return 0


def build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog)
    sub = parser.add_subparsers(dest="action", required=True)
    setup = sub.add_parser("setup")
    setup.add_argument("--email", required=True)
    setup.add_argument("--replace", action="store_true")
    sub.add_parser("list")
    search = sub.add_parser("search")
    search.add_argument("query")
    run = sub.add_parser("run")
    run.add_argument("-e", "--env", action="append", type=parse_mapping, default=[], dest="mappings")
    run.add_argument("--timeout", type=float)
    run.add_argument("command", nargs=argparse.REMAINDER)
    status = sub.add_parser("status")
    status.add_argument("--json", action="store_true")
    return parser


def sanitize_items_stream() -> int:
    try:
        raw = json.load(sys.stdin)
        if not isinstance(raw, list):
            return 1
        safe = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            name = item.get("name")
            if isinstance(item_id, str) and isinstance(name, str) and item_id and name.strip():
                safe.append({"id": item_id, "name": name.strip()})
        json.dump(safe, sys.stdout, separators=(",", ":"))
        return 0
    except (json.JSONDecodeError, OSError, ValueError):
        return 1


def die(message: str, code: int = 1) -> NoReturn:
    print(f"geheim: {message}", file=sys.stderr)
    raise SystemExit(code)


def main(argv: Sequence[str] | None = None, *, config_path: Path = DEFAULT_CONFIG) -> int:
    prog = Path(sys.argv[0]).name
    args = build_parser(prog).parse_args(argv)
    try:
        if prog == "geheim" and args.action == "setup":
            return command_setup(args.email, args.replace, config_path)
        config = Config.load(config_path)
        if args.action in ("list", "search"):
            return command_list(config, args.query if args.action == "search" else None)
        if args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            return command_run(config, args.mappings, command, args.timeout)
        if args.action == "status":
            bw = Bw(config)
            status = bw.status()
            if args.json:
                print(json.dumps({"status": status, "server": config.server, "bw_version": config.bw_version}))
            else:
                print(status)
            return 0
        raise GeheimError("Unknown command")
    except AuthenticationCancelled as exc:
        die(str(exc), 130)
    except GeheimError as exc:
        die(str(exc))
    return 1


if __name__ == "__main__":
    if sys.argv[1:] == ["__sanitize-items"]:
        raise SystemExit(sanitize_items_stream())
    raise SystemExit(main())
