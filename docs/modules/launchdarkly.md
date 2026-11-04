# LaunchDarkly

Projects, environments and flags with their state in an environment, and
turning a flag on or off in one environment.

**Setup.** In LaunchDarkly, open Organization settings, Authorization and
create an API access token: the Reader role can look, Writer can turn flags
on and off. Store it in the vault. Set `region` to `eu` or `federal` for
those instances; the default is `app.launchdarkly.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Key, name and tags. |
| `environments` | read | A project's environments: key, name, whether critical, whether changes need a comment, a confirmation or an approval, and tags. |
| `flags` | read | A project's flags in one environment: key, name, kind, temporary, tags, whether on and when last changed, with counts of on and off. |
| `flag` | read | One flag in one environment: on, version, variations by name, off and default variation, whether the default rule is a rollout, the number of individual targets, each rule's clause count, and prerequisites. |
| `turn_on` | destructive | Turns a flag's targeting on in one environment. The preview names the project, environment and flag, with the state and version before and the state after. Undo turns it off again. |
| `turn_off` | destructive | Turns a flag's targeting off, so everyone gets its off variation. The preview and undo work the same way. |

When the flag is already in the state asked for, the action answers
"nothing to change" and leaves it alone. Both actions send a JSON Patch with
a comment (`comment` from the input, or that it was done through Conduit):
a `test` that `/environments/<env>/on` still has the value just read, then a
`replace` of that one field. LaunchDarkly applies both or neither, so if
someone switched the flag in the meantime nothing is changed and the action
says so; targets, rules and variations are never touched.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Project,
environment and flag keys are checked before any request. Environment SDK
keys, mobile keys and client-side ids are never read. Targets and rules are
only counted: their values (context keys, emails) and variation values are
never returned.

## Notes

- Environments that require approvals refuse direct changes; the action
  then says to open an approval request in LaunchDarkly. The change is
  never retried another way.
