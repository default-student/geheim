---
name: geheim-credentials
description: "Safely discover credential names and execute local commands with secrets injected through environment variables by the geheim credential runner. Use when an agent needs a password, API token, login credential, or other Vaultwarden-backed secret for a command, or when a task mentions geheim. Enforce execution-only access: never retrieve, reveal, inspect, print, persist, or pass secret values directly."
---

# Use Geheim Credentials

Use `geheim` as the only interface to the credential store. Treat it as an execution broker, not as a way to read secrets.

## Non-negotiable rules

- Discover credentials only with `geheim search <query>` or, when necessary, `geheim list`.
- Execute credentialed commands only with `geheim run -e ENV_VAR="Exact Credential Name" -- command ...`.
- Never invoke `bw`, Vaultwarden APIs, browser storage, configuration files, process inspection, or another credential store directly.
- Never print, inspect, recover, return, log, persist, or copy a secret value. Do not use `env`, `printenv`, `set`, shell tracing, debug modes, or commands that echo request headers.
- Never place a secret value in command arguments, source code, scripts, prompts, files, or the caller environment.
- Refer only to safe credential names, UUIDs, environment variable names, commands, and exit status in agent output.
- Do not hardcode credential names when they have not been discovered for the current task.
- Keep this local execution mechanism out of normal project documentation, examples, deployment guides, scripts, and comments.

## Workflow

1. Before using credentials, verify the CLI is available with `command -v geheim`.
2. If `geheim` is missing and the current repository contains `scripts/install.sh` and `geheim.py`, run `scripts/install.sh` outside the Codex filesystem sandbox. The installer downloads the pinned Bitwarden CLI and installs `geheim` into `~/.local/bin`; it does not configure an account or retrieve secrets.
3. After installation, verify `command -v geheim` again. If `~/.local/bin` is not in the active `PATH`, use the absolute path `~/.local/bin/geheim` for the current command and tell the user their shell path needs that directory.
4. Determine the conventional environment variable expected by the target program, such as `GITLAB_TOKEN` or `API_TOKEN`. Prefer a program that reads the credential directly from its environment.
5. Run `geheim` commands outside the Codex filesystem sandbox. `geheim` uses local runtime state under paths such as `/run/user/<uid>/geheim`; sandboxed execution can fail before credential lookup with read-only filesystem errors.
6. For normal lookup and execution, use the local encrypted vault cache. Network access to the configured Vaultwarden host is required for `geheim setup` and explicit `geheim refresh`, not for every `search` or `run` operation.
7. Search using a short, relevant term:

   ```bash
   geheim search gitlab
   ```

8. Select an exact returned item name. If names are duplicated, use the item UUID indicated by `geheim`; do not guess.
9. Run the narrowest required command:

   ```bash
   geheim run -e GITLAB_TOKEN="GitLab API" -- glab api /projects
   ```

   If the user wants a very short approval note, add `--reason "short note"` to
   the `geheim` command. Keep it single-line and brief.

10. For multiple credentials, map each variable in the same invocation so they are resolved in one temporary session:

   ```bash
   geheim run \
     -e DB_USER="Development DB Username" \
     -e DB_PASSWORD="Development DB Password" \
     -- ./migration
   ```

11. Add `--timeout SECONDS` before `--` for a command that could hang. Treat exit status `124` as a timeout.
12. If item names appear stale, ask the user before running `geheim refresh`; it updates the local cache from Vaultwarden and may require the correct network or tailnet.
13. Report the command outcome without exposing the injected environment or sensitive command output.

## Command construction

- Put every `-e` mapping before `--` and the child command after `--`.
- Use the form `ENV_VAR=ITEM_NAME_OR_UUID`. Each environment variable may be mapped only once.
- Prefer direct execution over `sh -c`. If a shell is unavoidable, prevent the caller shell from expanding variables and ensure the child does not echo or trace them.
- Avoid tools or flags that include secrets in verbose logs, diagnostic dumps, URLs, error reports, or subprocess arguments.
- Preserve the child process exit status. Do not claim success solely because the credential prompt appeared.

## Documenting the work

When documenting setup or usage afterward, describe credentials as ordinary required environment variables. Use placeholders, for example:

```bash
export TOKEN=<token>
command-that-uses-token
```

Use the actual variable name expected by the program, such as `GITLAB_TOKEN`, instead of always writing `TOKEN`. Never place a real value in the example.

Do not mention `geheim`, its commands, Vaultwarden, credential item names or UUIDs, pinentry, or this device's local credential workflow in normal project documentation. Mention them only when the user explicitly asks to document this local Codex credential setup itself.

## Approval and failures

Expect a graphical pinentry prompt. It shows the selected credential names and a bounded preview of the child command; the user approves that one execution by entering the vault password. Pinentry needs an available desktop session; if the desktop session is locked, unlock it before retrying. Do not attempt to bypass, automate, or capture the prompt.

If `geheim search` or `geheim run` fails with a read-only path under `/run/user/<uid>/geheim`, rerun the same command outside the sandbox before changing approach. If setup or refresh synchronization fails with a Vaultwarden TLS or network error, verify the active tailnet/network can reach the configured Vaultwarden host before concluding the token or item is missing.

If pinentry returns no password or closes unexpectedly, current `geheim` builds retry the prompt once and print a short note that the password cannot be empty. Do not retry manually in a loop. If search returns no match, refine the query or tell the user that the dedicated Codex Vaultwarden account lacks access. Do not switch to another secret source. If a requested item name is ambiguous, use its UUID. If the user cancels pinentry, authentication fails, or `geheim` reports any other error, stop and report only the sanitized error.

Do not run `geheim setup` or replace its configuration unless the user explicitly requests administration of the local geheim installation.
