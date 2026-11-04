# Replicate

A [Replicate](https://replicate.com/) account: who the token belongs to,
models, recent predictions with status and run time, one prediction in
full, cancelling a running prediction, and deployments with their hardware
and scaling. Nothing here starts a run.

**Setup.** Create an API token at replicate.com, Account settings, API
tokens, and store it in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `account` | read | User or organization, username and name. |
| `models` | read | One `model` (`owner/name`) with description, visibility, run count, links and latest version, or a page of public models. `cursor` takes the `next` value of an earlier page. |
| `predictions` | read | Recent predictions, newest first: id, model and version, status, source (API or web), deployment, created, started and finished, run and total seconds, and any error. Inputs and outputs are left out. Paged with `cursor`. |
| `prediction` | read, sensitive | One prediction in full: everything above plus its input, output and logs. Inputs and outputs can hold personal data, so the action is sensitive and kept out of the audit log. |
| `cancel_prediction` | destructive | Stops a prediction that's starting or processing; its work so far is lost. The preview names the prediction, model and status, never its input. A finished prediction answers "nothing to change". No undo: a cancelled run can't be resumed. |
| `deployments` | read | Each deployment's current release: model and version, hardware, and minimum and maximum instances. Paged with `cursor`. |

**Security.** The token goes in the `Authorization` header to
`api.replicate.com` only; redirects are followed within the same host
only. Prediction ids, model names and cursors are checked before they reach
a request path or query. A prediction's webhook address (which can carry a
secret) and its streaming link are never read.

## Notes

- Replicate removes the inputs and outputs of API predictions after an
  hour; such predictions show `dataRemoved`.
- Run time used before a cancel is still billed.
