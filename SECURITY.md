# Security notes and acceptance tests

Never use a real credential value for leakage testing. Create a disposable
login item shared with the dedicated Codex Vaultwarden account and use a value
that is not displayed anywhere during the test.

The interactive acceptance run covers:

1. Locked status before and after successful list, search, and run.
2. Locked status after missing item, wrong password, cancelled pinentry,
   non-zero child, Ctrl+C, SIGTERM, timeout, and wrapper failure.
3. Disposable secret presence inside a child using `test -n "$TEST_SECRET"`.
4. No value in stdout, stderr, logs, history, argv, temporary files, the parent
   environment, or Codex output.
5. Search-to-run discovery using only the returned item name.
6. Vaultwarden access revocation followed by sync, failed search, and failed
   execution without a local allowlist change.

Do not place the disposable value in a command line, shell history, test
fixture, expected output, or conversation. Inspect only names, exit statuses,
file metadata, and whether a value is present.
