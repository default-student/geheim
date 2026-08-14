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
        self.__class__.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def sync(self):
        pass

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
            )
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("TEST_SECRET", os.environ)
        self.assertNotIn("disposable-value-not-printed", stdout.getvalue() + stderr.getvalue())
        prompt = FakeVault.instances[-1].prompt_details
        self.assertIn("TEST_SECRET <- Disposable Test", prompt)
        self.assertIn("test -n placeholder", prompt)
        self.assertNotIn("disposable-value-not-printed", prompt)

    def test_run_rejects_obvious_secret_printing_commands_before_vault(self):
        for command in (["echo", "$TEST_SECRET"], ["/usr/bin/echo", "$TEST_SECRET"], ["printenv"]):
            with self.subTest(command=command):
                FakeVault.instances.clear()
                with self.assertRaisesRegex(geheim.GeheimError, "Refusing to run"):
                    geheim.command_run(self.config, [("TEST_SECRET", "Disposable Test")], command, None)
                self.assertEqual(FakeVault.instances, [])

    def test_missing_message_contains_only_safe_suggestions(self):
        message = geheim.missing_message("GitLab API", ["GitLab API Token", "Grafana API"])
        self.assertIn("Credential \"GitLab API\" is not available.", message)
        self.assertIn("GitLab API Token", message)

    def test_public_cli_is_named_geheim(self):
        parser = geheim.build_parser("geheim")
        self.assertEqual(parser.parse_args(["list"]).action, "list")
        self.assertEqual(parser.parse_args(["search", "git"]).query, "git")
        parsed = parser.parse_args(["run", "-e", "TOKEN=GitLab API", "--", "true"])
        self.assertEqual(parsed.mappings, [("TOKEN", "GitLab API")])

    def test_empty_search_is_explicit(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", EmptyVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_list(self.config, "gitlab"), 0)
        self.assertEqual(output.getvalue(), 'No accessible credentials matched "gitlab".\n')

    def test_empty_list_is_explicit(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", EmptyVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_list(self.config, None), 0)
        self.assertEqual(output.getvalue(), "No accessible credentials are available.\n")

    def test_serve_stress_outputs_counts_not_items(self):
        output = io.StringIO()
        with mock.patch.object(geheim, "VaultOperation", EmptyVault), mock.patch("sys.stdout", output):
            self.assertEqual(geheim.command_serve_stress(self.config, "gitlab", 3), 0)
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
                geheim.command_setup("codex@example.invalid", False, None, config_path)

    def test_new_setup_requires_url(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.toml"
            with self.assertRaisesRegex(geheim.GeheimError, "--url"):
                geheim.command_setup("codex@example.invalid", False, None, config_path)

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
                geheim.command_setup("codex@example.invalid", False, "https://other-vault.example/", config_path)
        with self.assertRaises(geheim.GeheimError):
            geheim.normalize_server_url("http://vault.example/")
        self.assertEqual(
            geheim.normalize_server_url("https://VAULT.example/base"),
            "https://vault.example/base/",
        )


if __name__ == "__main__":
    unittest.main()
