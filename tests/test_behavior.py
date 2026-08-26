import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import geheim


class FakeVault:
    instances = []

    def __init__(self, config, operation, prompt_details=None):
        self.config = config
        self.operation = operation
        self.prompt_details = prompt_details
        self.closed = False
        self.sync_count = 0
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def sync(self):
        self.sync_count += 1

    def items(self, query=None):
        return [{"id": "test-id", "name": "Disposable Test"}]

    def password_for(self, item_id):
        self.assertion = item_id
        return "disposable-value-not-printed"

    def close_vault(self):
        self.closed = True


class FakePinentry:
    def __init__(self, path):
        pass

    def password(self, operation, email, details=None):
        return bytearray(b"correct horse")


class EmptyVault(FakeVault):
    def items(self, query=None):
        return []


class FakeChild:
    def __init__(self, command, env):
        assert command == ["test", "-n", "placeholder"]
        assert env["TEST_SECRET"] == "disposable-value-not-printed"
        assert "TEST_SECRET" not in os.environ
        assert FakeVault.instances[-1].closed

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


class FakeBwForSetup:
    instances = []

    def __init__(self, config):
        self.config = config
        self.calls = []
        self.__class__.instances.append(self)

    def lock(self, *, allow_unauthenticated=False):
        self.calls.append(("lock", allow_unauthenticated))
        return "unauthenticated"

    def run(self, args, **kwargs):
        self.calls.append(("run", tuple(args), kwargs.get("session")))
        if args[:1] == ["login"]:
            return subprocess.CompletedProcess(args, 0, "setup-session\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")


class ClosingPipe:
    def __init__(self):
        self.closed = False

    def write(self, data):
        raise BrokenPipeError()

    def flush(self):
        raise BrokenPipeError()

    def close(self):
        self.closed = True


class EarlyCloseStdout:
    def __init__(self):
        self.closed = False
        self.calls = 0

    def readline(self):
        self.calls += 1
        if self.calls == 1:
            return b"OK ready\n"
        return b""

    def close(self):
        self.closed = True


class EarlyClosePinentryProcess:
    instances = []

    def __init__(self, command, stdin, stdout, stderr, bufsize=None):
        self.command = command
        self.stdin = ClosingPipe()
        self.stdout = EarlyCloseStdout()
        self.bufsize = bufsize
        self.returncode = 1
        self.__class__.instances.append(self)

    def wait(self, timeout=None):
        return self.returncode


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        FakeVault.instances.clear()
        self.config = geheim.Config(
            email="codex@example.invalid",
            server="https://vault.example/",
            bw_path=Path("/does/not/matter"),
            bw_data_dir=Path("/does/not/matter"),
            pinentry_path=Path("/does/not/matter"),
            bw_version=geheim.BW_VERSION,
        )

    def test_sanitizer_emits_only_ids_and_names(self):
        payload = json.dumps(
            [{"id": "one", "name": "Safe Name", "login": {"password": "must-not-appear"}, "notes": "hidden"}]
        )
        result = subprocess.run(
            [sys.executable, str(Path(geheim.__file__)), "__sanitize-items"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout), [{"id": "one", "name": "Safe Name"}])
        self.assertNotIn("must-not-appear", result.stdout + result.stderr)
        self.assertNotIn("hidden", result.stdout + result.stderr)

    def test_run_injects_only_child_and_locks_before_child(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(geheim, "VaultOperation", FakeVault),
            mock.patch.object(geheim, "Pinentry", FakePinentry),
            mock.patch.object(geheim.subprocess, "Popen", FakeChild),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            result = geheim.command_run(
                self.config,
                [("TEST_SECRET", "Disposable Test")],
                ["test", "-n", "placeholder"],
                None,
                "short approval reason",
            )
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("TEST_SECRET", os.environ)
        self.assertNotIn("disposable-value-not-printed", stdout.getvalue() + stderr.getvalue())
        prompt = FakeVault.instances[-1].prompt_details
        self.assertIn("TEST_SECRET <- Disposable Test", prompt)
        self.assertIn("test -n placeholder", prompt)
        self.assertIn("Reason: short approval reason", prompt)
        self.assertNotIn("disposable-value-not-printed", prompt)
        self.assertEqual(FakeVault.instances[-1].sync_count, 0)

    def test_list_uses_cached_vault_without_sync(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", FakeVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_list(self.config, "gitlab", None), 0)
        self.assertEqual(output.getvalue(), "Disposable Test\n")
        self.assertEqual(FakeVault.instances[-1].operation, "search")
        self.assertEqual(FakeVault.instances[-1].sync_count, 0)

    def test_search_batches_terms_under_one_unlock_and_shows_them_in_prompt(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", FakeVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_list(self.config, ["gitlab", "grafana"], None), 0)
        self.assertEqual(output.getvalue(), "Disposable Test\n")
        self.assertEqual(len(FakeVault.instances), 1)
        prompt = FakeVault.instances[-1].prompt_details
        self.assertIn("Searches:\n  gitlab\n  grafana", prompt)

    def test_refresh_syncs_cached_vault_on_demand(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", FakeVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_refresh(self.config, None), 0)
        self.assertEqual(output.getvalue(), "Credential cache refreshed.\n")
        self.assertEqual(FakeVault.instances[-1].operation, "refresh")
        self.assertEqual(FakeVault.instances[-1].sync_count, 1)

    def test_run_rejects_obvious_secret_printing_commands_before_vault(self):
        for command in (["echo", "$TEST_SECRET"], ["/usr/bin/echo", "$TEST_SECRET"], ["printenv"]):
            with self.subTest(command=command):
                FakeVault.instances.clear()
                with self.assertRaisesRegex(geheim.GeheimError, "Refusing to run"):
                    geheim.command_run(self.config, [("TEST_SECRET", "Disposable Test")], command, None, None)
                self.assertEqual(FakeVault.instances, [])

    def test_pinentry_early_close_is_cleaned_up(self):
        EarlyClosePinentryProcess.instances.clear()
        pinentry = geheim.Pinentry(Path("/tmp/pinentry"))
        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(geheim.subprocess, "Popen", EarlyClosePinentryProcess),
            mock.patch("sys.stderr", io.StringIO()),
        ):
            with self.assertRaisesRegex(geheim.GeheimError, "pinentry closed unexpectedly"):
                pinentry.password("test", "codex@example.invalid")
        self.assertEqual(len(EarlyClosePinentryProcess.instances), 2)
        proc = EarlyClosePinentryProcess.instances[-1]
        self.assertEqual(proc.bufsize, 0)
        self.assertTrue(proc.stdin.closed)
        self.assertTrue(proc.stdout.closed)

    def test_pinentry_empty_response_retries_once_with_note(self):
        pinentry = geheim.Pinentry(Path("/tmp/pinentry"))
        stderr = io.StringIO()
        with (
            mock.patch.object(
                geheim.Pinentry,
                "_exchange",
                side_effect=[geheim.PinentryRetryableError("pinentry returned no password"), bytearray(b"safe")],
            ) as exchange,
            mock.patch("sys.stderr", stderr),
        ):
            result = pinentry.password("test", "codex@example.invalid")
        self.assertEqual(result, bytearray(b"safe"))
        self.assertEqual(exchange.call_count, 2)
        self.assertEqual(stderr.getvalue(), "geheim: pinentry returned no password; password cannot be empty, try again.\n")
        retry_commands = exchange.call_args_list[1].args[0]
        self.assertIn(b"SETERROR Password cannot be empty. Please try again.", retry_commands)

    def test_pinentry_explicit_empty_password_retries_once(self):
        pinentry = geheim.Pinentry(Path("/tmp/pinentry"))
        proc = mock.Mock()
        proc.stdin = io.BytesIO()
        proc.stdout = io.BytesIO(b"OK ready\nD \nOK\n")
        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(geheim.subprocess, "Popen", return_value=proc),
        ):
            with self.assertRaisesRegex(geheim.PinentryRetryableError, "pinentry returned no password"):
                pinentry._exchange([b"GETPIN"], expect_data=True)

    def test_missing_message_contains_only_safe_suggestions(self):
        message = geheim.missing_message("GitLab API", ["GitLab API Token", "Grafana API"])
        self.assertIn("Credential \"GitLab API\" is not available.", message)
        self.assertIn("GitLab API Token", message)
        self.assertIn("geheim refresh", message)

    def test_public_cli_is_named_geheim(self):
        parser = geheim.build_parser("geheim")
        self.assertEqual(parser.parse_args(["list"]).action, "list")
        self.assertEqual(parser.parse_args(["refresh"]).action, "refresh")
        self.assertEqual(parser.parse_args(["search", "git"]).queries, ["git"])
        self.assertEqual(parser.parse_args(["search", "git", "grafana"]).queries, ["git", "grafana"])
        self.assertEqual(parser.parse_args(["search", "gitlab token", "grafana"]).queries, ["gitlab token", "grafana"])
        parsed = parser.parse_args(["run", "-e", "TOKEN=GitLab API", "--", "true"])
        self.assertEqual(parsed.mappings, [("TOKEN", "GitLab API")])

    def test_command_preview_summarizes_long_argument(self):
        preview = geheim.command_preview(["python3", "-c", "x" * 600])
        self.assertIn("python3 -c", preview)
        self.assertIn("argument 3 omitted: 600 characters", preview)
        self.assertIn("command preview shortened", preview)
        self.assertNotIn("x" * 600, preview)

    def test_empty_search_is_explicit(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", EmptyVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_list(self.config, "gitlab", None), 0)
        self.assertEqual(output.getvalue(), 'No accessible credentials matched "gitlab".\n')

    def test_empty_list_is_explicit(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", EmptyVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_list(self.config, None, None), 0)
        self.assertEqual(output.getvalue(), "No accessible credentials are available.\n")

    def test_serve_stress_outputs_counts_not_items(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", EmptyVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_serve_stress(self.config, "gitlab", 3, None), 0)
        result = output.getvalue()
        self.assertIn("serve_requests=3", result)
        self.assertIn("serve_failures=0", result)
        self.assertIn("locked_after_test=yes", result)
        self.assertNotIn("Disposable Test", result)

    def test_config_is_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = geheim.Config(
                email="codex@example.invalid",
                server="https://vault.example/",
                bw_path=root / "bw",
                bw_data_dir=root / "data",
                pinentry_path=Path("/usr/bin/pinentry-gnome3"),
                bw_version=geheim.BW_VERSION,
            )
            path = root / "config" / "config.toml"
            geheim.write_config(config, path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(config.bw_data_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(geheim.Config.load(path), config)

    def test_initial_lock_accepts_only_confirmed_unauthenticated_state(self):
        bw = object.__new__(geheim.Bw)
        bw.run = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "not logged in"))
        bw.status = mock.Mock(return_value="unauthenticated")
        self.assertEqual(bw.lock(allow_unauthenticated=True), "unauthenticated")
        bw.status.return_value = "unlocked"
        with self.assertRaises(geheim.GeheimError):
            bw.lock(allow_unauthenticated=True)

    def test_existing_setup_reports_remote_server(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            config = geheim.Config(
                email="codex@example.invalid",
                server="https://vault.example/",
                bw_path=Path("/tmp/bw"),
                bw_data_dir=Path(directory) / "bw-data",
                pinentry_path=Path("/tmp/pinentry"),
                bw_version=geheim.BW_VERSION,
            )
            geheim.write_config(config, config_path)
            with self.assertRaisesRegex(geheim.GeheimError, "https://vault.example/"):
                geheim.command_setup("codex@example.invalid", False, None, config_path, None)

    def test_new_setup_requires_url(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            with self.assertRaisesRegex(geheim.GeheimError, "--url"):
                geheim.command_setup("codex@example.invalid", False, None, config_path, None)

    def test_url_change_requires_replace_and_https(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            config = geheim.Config(
                email="codex@example.invalid",
                server="https://vault.example/",
                bw_path=Path("/tmp/bw"),
                bw_data_dir=Path(directory) / "bw-data",
                pinentry_path=Path("/tmp/pinentry"),
                bw_version=geheim.BW_VERSION,
            )
            geheim.write_config(config, config_path)
            with self.assertRaisesRegex(geheim.GeheimError, "--replace"):
                geheim.command_setup("codex@example.invalid", False, "https://other-vault.example/", config_path, None)
        with self.assertRaises(geheim.GeheimError):
            geheim.normalize_server_url("http://vault.example/")
        self.assertEqual(
            geheim.normalize_server_url("https://VAULT.example/base"),
            "https://vault.example/base/",
        )

    def test_setup_logs_in_and_refreshes_initial_cache(self):
        FakeBwForSetup.instances.clear()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            stdout = io.StringIO()
            with (
                mock.patch.object(geheim, "Bw", FakeBwForSetup),
                mock.patch.object(geheim, "Pinentry", FakePinentry),
                mock.patch.object(geheim, "DEFAULT_BW_DATA", Path(directory) / "bw-data"),
                mock.patch.object(geheim, "DEFAULT_BW", Path(directory) / "bw"),
                mock.patch("sys.stdout", stdout),
            ):
                self.assertEqual(
                    geheim.command_setup(
                        "codex@example.invalid",
                        False,
                        "https://vault.example/",
                        config_path,
                        None,
                    ),
                    0,
                )
        bw = FakeBwForSetup.instances[-1]
        self.assertIn(("run", ("sync",), "setup-session"), bw.calls)
        self.assertIn("vault cache refreshed and status is locked", stdout.getvalue())

    def test_parser_accepts_reason_on_multiple_commands(self):
        parser = geheim.build_parser("geheim")
        self.assertEqual(parser.parse_args(["list", "--reason", "approval note"]).reason, "approval note")
        self.assertEqual(
            parser.parse_args(["run", "--reason", "approval note", "-e", "TOKEN=GitLab API", "--", "true"]).reason,
            "approval note",
        )
        self.assertEqual(parser.parse_args(["self-test", "--reason", "approval note", "serve"]).reason, "approval note")
        self.assertEqual(
            parser.parse_args(["self-test", "serve", "--reason", "approval note"]).serve_reason,
            "approval note",
        )


if __name__ == "__main__":
    unittest.main()
