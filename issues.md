# Known Issues

## Cached credential access across Tailscale profiles

### Current environment

This workstation uses two Tailscale profiles:

- `Home` provides access to the configured Vaultwarden service.
- `Hadi` is the profile that may need to remain active during work.

Do not switch Tailscale profiles automatically. A profile change must be an
explicit user action.

### Symptom

When `Hadi` is active, a credential search can fail with errors such as:

```text
geheim: Credential discovery failed: The short-lived Vaultwarden service request failed
```

or:

```text
geheim: Credential discovery failed: Vaultwarden TLS verification failed.
```

The configured Vaultwarden hostname belongs to the `Home` Tailnet. It does not
resolve through the active `Hadi` Tailnet, so the Tailscale TCP relay cannot
reach the service.

### Why the encrypted Bitwarden cache is insufficient

Normal `geheim search` and `geheim run` operations were intended to use the
local encrypted Bitwarden cache, with network synchronization limited to
`geheim setup` and `geheim refresh`.

Current Bitwarden CLI releases still make server-configuration and token
requests while unlocking, listing, or retrieving cached objects. When the
self-hosted server is unreachable, these operations may return no usable item
data. Accepting a failed command without structurally valid output would weaken
the credential-safety boundary, so Geheim must continue to reject it.

Relevant upstream reports:

- [CLI get password fails offline](https://github.com/bitwarden/clients/issues/20195)
- [CLI 2026.3.0 and newer unlock regression](https://github.com/bitwarden/clients/issues/20703)
- [CLI status and unlock return failures while offline](https://github.com/bitwarden/clients/issues/18373)

### Investigated approaches

- Replacing the local `bw serve` Unix-socket transport with an isolated TCP
  bridge did not solve the issue. The CLI still contacted Vaultwarden while
  starting or unlocking.
- Direct cached `bw list` and `bw get` operations also failed because the CLI
  attempted remote token requests and returned no valid item data.
- Treating network-related exit codes as success was rejected because no valid
  sanitized output was available.

All experimental changes were removed. The validated repository version was
reinstalled, the global `geheim-credentials` skill was synchronized, installed
file parity was confirmed, and the 28-test suite passed.

### Safe follow-up options

1. While the user has manually activated `Home`, test Bitwarden CLI `2026.1.0`
   and perform the fresh login required after downgrade. Verify `search` and
   credential injection again after returning to `Hadi` before adopting that
   version. The older release is reported to fix a related unlock regression,
   but fully offline retrieval is not yet proven here.
2. Run a separate userspace Tailscale instance enrolled in `Home`, leaving the
   system `Hadi` profile untouched. This requires explicit approval and separate
   Home authentication or enrollment.
3. Provide the Vaultwarden service through an explicitly approved route that is
   reachable without changing the active Tailscale profile.

Do not claim the issue fixed until a live `geheim search` succeeds and a
credential can be injected into a harmless child command while `Hadi` remains
the active system profile.
