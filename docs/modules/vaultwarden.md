# Vaultwarden

Keeps an eye on a Vaultwarden server without touching anyone's passwords.
Every action is read-only.

**Setup.** Enter the server's address, such as `https://vault.example.com`.
For account counts, also store the server's `ADMIN_TOKEN` (the plain token
you type on `/admin`, not its Argon2 hash) in the vault and add its
`secret://` reference. The `/admin` page must be turned on.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Whether `/alive` answers, the response time, and the version and name from `/api/config`. |
| `accounts` | read | Counts only: total, disabled, enabled without two-factor sign-in, not active for 90 days. No names or emails leave the module. Needs the admin token. |

Health is `down` when the server doesn't answer and `degraded` when it takes
more than 3 seconds.
