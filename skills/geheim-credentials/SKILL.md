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

## Workflow

1. Determine the conventional environment variable expected by the target program, such as `GITLAB_TOKEN` or `API_TOKEN`. Prefer a program that reads the credential directly from its environment.
2. Search using a short, relevant term:

   ```bash
   geheim search gitlab
   ```

3. Select an exact returned item name. If names are duplicated, use the item UUID indicated by `geheim`; do not guess.
4. Run the narrowest required command:

   ```bash
   geheim run -e GITLAB_TOKEN="GitLab API" -- glab api /projects
   ```

5. For multiple credentials, map each variable in the same invocation so they are resolved in one temporary session:

   ```bash
   geheim run \
     -e DB_USER="Development DB Username" \
     -e DB_PASSWORD="Development DB Password" \
     -- ./migration
   ```

6. Add `--timeout SECONDS` before `--` for a command that could hang. Treat exit status `124` as a timeout.
7. Report the command outcome without exposing the injected environment or sensitive command output.

## Command construction

- Put every `-e` mapping before `--` and the child command after `--`.
- Use the form `ENV_VAR=ITEM_NAME_OR_UUID`. Each environment variable may be mapped only once.
- Prefer direct execution over `sh -c`. If a shell is unavoidable, prevent the caller shell from expanding variables and ensure the child does not echo or trace them.
- Avoid tools or flags that include secrets in verbose logs, diagnostic dumps, URLs, error reports, or subprocess arguments.
- Preserve the child process exit status. Do not claim success solely because the credential prompt appeared.

## Approval and failures

Expect a graphical pinentry prompt. It shows the selected credential names and child command; the user approves that one execution by entering the vault password. Do not attempt to bypass, automate, or capture the prompt.

If search returns no match, refine the query or tell the user that the dedicated Codex Vaultwarden account lacks access. Do not switch to another secret source. If a requested item name is ambiguous, use its UUID. If the user cancels pinentry, authentication fails, or `geheim` reports an error, stop and report only the sanitized error.

Do not run `geheim setup` or replace its configuration unless the user explicitly requests administration of the local geheim installation.
