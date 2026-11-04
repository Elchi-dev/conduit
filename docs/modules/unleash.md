# Unleash

Projects, features with their state in each environment and their
activation strategies, and turning a feature on or off in one environment,
on a self-hosted Unleash server or Unleash Cloud.

**Setup.** In Unleash, open Admin, API access and create an admin token, or
create a personal access token from your profile; store it in the vault.
Enter your Unleash address, such as `https://unleash.example.com`, or your
Unleash Cloud instance, such as `https://eu.app.unleash-hosted.com/abc123`.
The token acts with its role: a viewer can look, turning features on and
off needs a role that may change them. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Id, name, description, health, feature and member counts, and the project's mode. |
| `features` | read | A project's features (`default` unless `project` is given): name, type, description, stale, last seen, and whether it's on in each environment. |
| `strategies` | read | One feature's strategies per environment (or one, with `environment`): kind, title, disabled, rollout, stickiness and group id, segment and variant counts, and each constraint's context, operator and how many values it matches. |
| `turn_on` | destructive | Turns a feature on in one environment. The preview names the project, environment (and its type) and feature, with the state before and after. Undo turns it off again. |
| `turn_off` | destructive | Turns a feature off in one environment. The preview and undo work the same way. |

When the feature is already in the state asked for, the action answers
"nothing to change" and leaves it alone. Both actions use Unleash's on and
off endpoints, which change only that environment's switch, so strategies,
variants and other environments stay exactly as they are, including
changes someone made after the preview. The endpoints answer without a
body, so the action reads the feature back and fails if the switch didn't
move.

Turning a feature on in an environment with no active strategy makes
Unleash add that environment's default strategy (usually a 100% rollout);
the preview says so. Turning it off again (the undo) leaves that strategy
in place, which has no effect while the feature is off.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Project,
feature and environment names must be plain identifiers before they reach a
request path. Constraint values and strategy parameters that can name users
(user ids, IP addresses, host names) are never returned; only their kind,
count or parameter name is.

## Notes

- Projects that need change requests refuse direct changes; the action
  then fails with Unleash's explanation.
- Unleash's toggle endpoints don't take a version, so a turn is a plain
  on or off rather than a compare-and-set.
