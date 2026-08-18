#!/usr/bin/env python3
"""Local, execution-only Bitwarden/Vaultwarden credential runner."""

from __future__ import annotations

import argparse
import difflib
import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
from dataclasses import dataclass
from typing import NoReturn, Sequence


BW_VERSION = "2026.7.0"
DEFAULT_CONFIG = Path.home() / ".config" / "geheim" / "config.toml"
DEFAULT_BW_DATA = Path.home() / ".local" / "share" / "geheim" / "bw-data"
DEFAULT_BW = Path.home() / ".local" / "lib" / "geheim" / f"bw-{BW_VERSION}" / "bw"
DEFAULT_PINENTRY = Path(
    os.environ.get("GEHEIM_PINENTRY")
    or shutil.which("pinentry-gnome3")
    or shutil.which("pinentry")
    or "/usr/bin/pinentry-gnome3"
)
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DENIED_RUN_COMMANDS = {
    "declare",
    "echo",
    "env",
    "export",
    "printenv",
    "printf",
    "set",
    "typeset",
}
HOST_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class GeheimError(Exception):
    pass


class AuthenticationCancelled(GeheimError):
    pass


class PinentryRetryableError(GeheimError):
    pass


def normalize_server_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
        or not HOST_NAME.fullmatch(parsed.hostname)
    ):
        raise GeheimError("Vaultwarden URL must be an HTTPS hostname on port 443 without credentials, query, or fragment.")
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(("https", parsed.hostname.lower(), path + "/", "", ""))


def write_network_hosts(config: "Config") -> Path:
    hostname = urllib.parse.urlsplit(config.server).hostname
    if hostname is None:
        raise GeheimError("Configured Vaultwarden URL has no hostname")
    path = config.bw_data_dir / "network-hosts"
    path.write_text(f"127.0.0.1 localhost {hostname}\n::1 localhost ip6-localhost ip6-loopback\n")
    os.chmod(path, 0o600)
    return path


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
        if normalize_server_url(cfg.server) != cfg.server:
            raise GeheimError(f"Invalid server in configuration: {cfg.server}")
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
            [str(self.executable)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        assert proc.stdin is not None and proc.stdout is not None
        pinentry_stdin = proc.stdin
        pinentry_stdout = proc.stdout
        data: bytearray | None = None
        try:
            greeting = pinentry_stdout.readline()
            if not greeting.startswith(b"OK"):
                raise GeheimError("pinentry did not start correctly")
            for command in commands:
                try:
                    pinentry_stdin.write(command + b"\n")
                    pinentry_stdin.flush()
                except (BrokenPipeError, OSError) as exc:
                    raise PinentryRetryableError("pinentry closed unexpectedly") from exc
                while True:
                    line = pinentry_stdout.readline()
                    if not line:
                        raise PinentryRetryableError("pinentry closed unexpectedly")
                    line = line.rstrip(b"\r\n")
                    if line.startswith(b"D "):
                        data = bytearray(_pinentry_unescape(line[2:]))
                    elif line.startswith(b"OK"):
                        break
                    elif line.startswith(b"ERR"):
                        if b"cancel" in line.lower():
                            raise AuthenticationCancelled("Authentication was cancelled.")
                        raise GeheimError("pinentry rejected the request")
            if expect_data and not data:
                raise PinentryRetryableError("pinentry returned no password")
            return data
        finally:
            try:
                pinentry_stdin.write(b"BYE\n")
                pinentry_stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            try:
                pinentry_stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                pinentry_stdout.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def password(self, operation: str, email: str, details: str | None = None) -> bytearray:
        description = f"Unlock the Codex Vaultwarden account for one {operation} operation.\nAccount: {email}"
        if details:
            description += f"\n\n{details}"
        base_commands = [
            b"SETTITLE geheim Vaultwarden authentication",
            b"SETDESC " + _pinentry_escape(description),
            b"SETPROMPT Master password:",
            b"SETOK Unlock once",
            b"SETCANCEL Cancel",
        ]
        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            commands = [*base_commands]
            if attempt > 1:
                commands.append(b"SETERROR " + _pinentry_escape("Password cannot be empty. Please try again."))
            commands.append(b"GETPIN")
            try:
                result = self._exchange(commands, expect_data=True)
                break
            except PinentryRetryableError as exc:
                if attempt == max_attempts:
                    raise
                print(f"geheim: {exc}; password cannot be empty, try again.", file=sys.stderr)
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
        hosts = self.config.bw_data_dir / "network-hosts"
        bwrap = shutil.which("bwrap") or "/usr/bin/bwrap"
        python = shutil.which("python3") or "/usr/bin/python3"
        if not runner.is_file():
            raise GeheimError("geheim network-isolation support files are missing")
        write_network_hosts(self.config)
        target_host = urllib.parse.urlsplit(self.config.server).hostname
        assert target_host is not None
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/geheim-{os.getuid()}")) / "geheim"
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(runtime, 0o700)
        return [
            bwrap,
            "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "CAP_NET_BIND_SERVICE",
            "--unshare-net", "--die-with-parent", "--new-session",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--bind", str(self.config.bw_data_dir), str(self.config.bw_data_dir),
            "--bind", str(runtime), str(runtime),
            "--ro-bind", str(hosts), "/etc/hosts",
            python, str(runner), "--target-host", target_host, "--", *command,
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


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float = 20):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        import socket

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.socket_path))


class BwServeSession:
    def __init__(self, config: Config):
        self.config = config
        self.bw = Bw(config)
        self.runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/geheim-{os.getuid()}")) / "geheim"
        self.socket_path = self.runtime / f"bw-serve-{os.getpid()}.sock"
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.runtime, 0o700)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        hostname = f"unix://{self.socket_path}"
        self.process = subprocess.Popen(
            self.bw._command(["serve", "--hostname", hostname, "--port", "8087"]),
            env=self.bw._base_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.socket_path.exists():
                os.chmod(self.socket_path, 0o600)
                return
            if self.process.poll() is not None:
                break
            time.sleep(0.02)
        self.stop()
        raise GeheimError("The short-lived Vaultwarden service did not start")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    def request(self, method: str, path: str, body: dict | None = None) -> object:
        connection = UnixHTTPConnection(self.socket_path)
        encoded: bytes | None = None
        headers = {"Host": f"unix://{self.socket_path}:8087"}
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            payload = response.read()
        except (OSError, http.client.HTTPException) as exc:
            raise GeheimError("The short-lived Vaultwarden service request failed") from exc
        finally:
            connection.close()
            encoded = None
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise GeheimError("The short-lived Vaultwarden service returned invalid data") from exc
        if response.status != 200 or not isinstance(decoded, dict) or not decoded.get("success"):
            message = ""
            if isinstance(decoded, dict):
                message = str(decoded.get("message", ""))
            raise GeheimError(_safe_bw_error(message) or "Vaultwarden operation failed.")
        return decoded.get("data")

    def status(self) -> str:
        data = self.request("GET", "/status")
        template = data.get("template") if isinstance(data, dict) else None
        if not isinstance(template, dict) or template.get("status") not in ("locked", "unlocked", "unauthenticated"):
            raise GeheimError("The short-lived Vaultwarden service returned an invalid status")
        return str(template["status"])

    def lock(self) -> None:
        self.request("POST", "/lock")

    def unlock(self, password: bytearray) -> None:
        password_text = password.decode("utf-8")
        try:
            self.request("POST", "/unlock", {"password": password_text})
        finally:
            password_text = ""
        if self.status() != "unlocked":
            raise GeheimError("Vaultwarden did not enter the temporary unlocked state")

    def sync(self) -> None:
        self.request("POST", "/sync")

    def safe_items(self, query: str | None = None) -> list[dict[str, str]]:
        path = "/list/object/items"
        if query:
            path += "?" + urllib.parse.urlencode({"search": query})
        wrapped = self.request("GET", path)
        raw_items = wrapped.get("data") if isinstance(wrapped, dict) else None
        if not isinstance(raw_items, list):
            raise GeheimError("The short-lived Vaultwarden service returned an invalid item list")
        safe: list[dict[str, str]] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            name = item.get("name")
            if isinstance(item_id, str) and isinstance(name, str) and item_id and name.strip():
                safe.append({"id": item_id, "name": name.strip()})
            item.clear()
        raw_items.clear()
        return safe

    def password_for(self, item_id: str) -> str:
        path = "/object/password/" + urllib.parse.quote(item_id, safe="")
        wrapped = self.request("GET", path)
        value = wrapped.get("data") if isinstance(wrapped, dict) else None
        if not isinstance(value, str) or not value:
            raise GeheimError("The selected credential has no login password value.")
        return value

    def __enter__(self) -> "BwServeSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.stop()
        return False


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
    def __init__(self, config: Config, operation: str, prompt_details: str | None = None):
        self.config = config
        self.operation = operation
        self.serve = BwServeSession(config)
        self.pinentry = Pinentry(config.pinentry_path)
        self.prompt_details = prompt_details
        self.vault_closed = False
        self._lock_handle = None

    def __enter__(self) -> "VaultOperation":
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/geheim-{os.getuid()}")) / "geheim"
        runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(runtime, 0o700)
        self._lock_handle = (runtime / "operation.lock").open("a+")
        fcntl.flock(self._lock_handle, fcntl.LOCK_EX)
        try:
            self.serve.start()
            self.serve.lock()
            if self.serve.status() != "locked":
                raise GeheimError("Vaultwarden did not enter the required locked state")
            password = self.pinentry.password(self.operation, self.config.email, self.prompt_details)
            try:
                self.serve.unlock(password)
            finally:
                for index in range(len(password)):
                    password[index] = 0
            return self
        except BaseException:
            try:
                try:
                    self.serve.lock()
                finally:
                    self.serve.stop()
            finally:
                fcntl.flock(self._lock_handle, fcntl.LOCK_UN)
                self._lock_handle.close()
                self._lock_handle = None
            raise

    def close_vault(self) -> None:
        if self.vault_closed:
            return
        try:
            self.serve.lock()
            if self.serve.status() != "locked":
                raise GeheimError("Vaultwarden did not return to locked state")
        finally:
            self.serve.stop()
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
        self.serve.sync()

    def items(self, query: str | None = None) -> list[dict]:
        return self.serve.safe_items(query)

    def password_for(self, item_id: str) -> str:
        return self.serve.password_for(item_id)


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


def validate_child_command(command: Sequence[str]) -> None:
    executable = Path(command[0]).name
    if executable in DENIED_RUN_COMMANDS:
        raise GeheimError(f"Refusing to run {executable!r} with injected credentials")


def command_preview(command: Sequence[str], limit: int = 480) -> str:
    rendered = shlex.join(command)
    if len(rendered) <= limit:
        return rendered
    preview: list[str] = []
    used = 0
    for index, argument in enumerate(command):
        quoted = shlex.quote(argument)
        separator = 1 if preview else 0
        if used + separator + len(quoted) > limit:
            preview.append(f"<argument {index + 1} omitted: {len(argument)} characters>")
            break
        preview.append(quoted)
        used += separator + len(quoted)
    return " ".join(preview) + f" <command preview shortened: {len(rendered)} characters total>"


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
    validate_child_command(command)
    safe_mappings = "\n".join(f"{name} <- {item}" for name, item in mappings)
    prompt_details = f"Credentials:\n{safe_mappings}\n\nCommand:\n{command_preview(command)}"
    secrets: dict[str, str] = {}
    with VaultOperation(config, "geheim run", prompt_details) as vault:
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


def command_setup(email: str, replace: bool, url: str | None, config_path: Path) -> int:
    if url is not None and config_path.exists() and not replace:
        raise GeheimError("--url may only be used together with --replace")
    if config_path.exists() and not replace:
        previous = Config.load(config_path)
        raise GeheimError(
            f"geheim is already configured for remote Vaultwarden {previous.server} at {config_path}. "
            "Use --replace to change the dedicated account."
        )
    previous: Config | None = None
    if config_path.exists():
        previous = Config.load(config_path)
    if url is None and previous is None:
        raise GeheimError('geheim setup requires --url https://vaultwarden.example.com/ for a new configuration.')
    server = normalize_server_url(url) if url is not None else previous.server
    config = Config(
        email=email,
        server=server,
        bw_path=DEFAULT_BW,
        bw_data_dir=DEFAULT_BW_DATA,
        pinentry_path=DEFAULT_PINENTRY,
        bw_version=BW_VERSION,
        network_enforcement="bubblewrap-tailscale",
    )
    setup_details = f"Remote Vaultwarden:\n{server}"
    config.bw_data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(config.bw_data_dir, 0o700)
    same_account_reset = (
        replace
        and previous is not None
        and previous.email == email
        and previous.server == server
    )
    if same_account_reset:
        with VaultOperation(config, "setup verification", setup_details):
            pass
        write_config(config, config_path)
        print(
            f"Configured dedicated Vaultwarden account {email} for {server}; "
            "vault status is locked."
        )
        return 0
    bw = Bw(config)
    pinentry = Pinentry(config.pinentry_path)
    status = bw.lock(allow_unauthenticated=True)
    try:
        if status != "unauthenticated":
            if not replace:
                raise GeheimError("The isolated bw state already contains a logged-in account.")
            result = bw.run(["logout"], check=False)
            if result.returncode != 0:
                raise GeheimError("Could not log out the previously configured Vaultwarden account.")
        bw.run(["config", "server", server])
        password = pinentry.password("initial login", email, setup_details)
        try:
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
    print(
        f"Configured dedicated Vaultwarden account {email} for {server}; "
        "vault status is locked."
    )
    return 0


def command_serve_stress(config: Config, query: str, iterations: int) -> int:
    if iterations < 1 or iterations > 1000:
        raise GeheimError("Serve stress iterations must be between 1 and 1000")
    failures = 0
    started = time.monotonic()
    with VaultOperation(config, "serve stress test") as vault:
        for index in range(iterations):
            try:
                if index % 25 == 0:
                    vault.sync()
                items = vault.items(query)
                for item in items:
                    item.clear()
                items.clear()
            except GeheimError:
                failures += 1
    elapsed = time.monotonic() - started
    print(f"serve_requests={iterations}")
    print(f"serve_failures={failures}")
    print(f"elapsed_seconds={elapsed:.3f}")
    print("locked_after_test=yes")
    return 0 if failures == 0 else 1


def build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog)
    sub = parser.add_subparsers(dest="action", required=True)
    setup = sub.add_parser("setup")
    setup.add_argument("--email", required=True)
    setup.add_argument("--replace", action="store_true")
    setup.add_argument("--url")
    sub.add_parser("list")
    search = sub.add_parser("search")
    search.add_argument("query")
    run = sub.add_parser("run")
    run.add_argument("-e", "--env", action="append", type=parse_mapping, default=[], dest="mappings")
    run.add_argument("--timeout", type=float)
    run.add_argument("command", nargs=argparse.REMAINDER)
    status = sub.add_parser("status")
    status.add_argument("--json", action="store_true")
    status.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    self_test = sub.add_parser("self-test")
    self_test_sub = self_test.add_subparsers(dest="test_action", required=True)
    serve_test = self_test_sub.add_parser("serve")
    serve_test.add_argument("--query", default="")
    serve_test.add_argument("--iterations", type=int, default=250)
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
            return command_setup(args.email, args.replace, args.url, config_path)
        config = Config.load(config_path)
        if args.action in ("list", "search"):
            return command_list(config, args.query if args.action == "search" else None)
        if args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            return command_run(config, args.mappings, command, args.timeout)
        if args.action == "self-test" and args.test_action == "serve":
            return command_serve_stress(config, args.query, args.iterations)
        if args.action == "status":
            if args.serve:
                with BwServeSession(config) as serve:
                    status = serve.status()
            else:
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
