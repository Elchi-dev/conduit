# Conduit for developers

You'll connect a server, Docker, GitHub and Sentry, pin what you check most
to your board, and let an AI agent restart a broken service, with your
approval of the exact change.

## 1. Connect your systems

1. **Modules, Server (SSH).** Add a host, a user and a private key. Store
   the key in the vault when asked; Conduit only keeps a `secret://`
   reference in the settings.
2. **Docker.** Local socket, or the same SSH host.
3. **GitHub** (or GitLab) with a fine-grained token for the repositories
   you care about, and **Sentry** with an auth token limited to
   `project:read` and `event:admin` if you want to resolve issues.

Each system gets a lamp in the top row. A red lamp means its health check
failed; open it to see why.

## 2. Build your board

Open a module and run a read action, such as **This computer → Status** or
**GitHub → Pull requests**. Under the result choose **Pin to home**, pick the
number to show (for example `cpu.percent`) and how often to update. Pinned
tiles appear on Overview under **Your board**.

## 3. Let an agent help, safely

1. **Assistant and agents.** Pick a model: a local one (Ollama, LM Studio)
   is detected automatically; or paste an API key; or point at your
   company's gateway.
2. **Agent rules.** The default preset, *Ask before changes*, lets agents
   read but holds every change for your approval.
3. Open **Assistant** in the top bar and ask *"nginx on web-2 is returning 502s,
   find out why and fix it"*. It reads logs and status freely; when it wants
   to restart the service, you get an approval with the exact command and
   its preview. Approve it on the desktop, in the app, or with your
   fingerprint on your phone.
4. Everything it did is in **Timeline**, and reversible actions have an
   **Undo**.

Prefer your own tools? Connect Claude Code, Cursor or any MCP client:
**Assistant and agents → Connect an outside agent** shows the command. The
same rules apply to them.

## 4. Automate the boring part

When you've fixed something by hand, open **Timeline**, select the steps and
choose **Save as automation**. Give it a trigger: a schedule, an event
(`web.down`, `server.down`) or a webhook from your CI. Automations you
save yourself run without asking; anything an agent drafts waits for you
to switch it on.

## 5. From the terminal

```sh
conduit login                      # with an API key from Settings → API keys
conduit run docker restart name=api --dry-run
conduit events --type action. --json | jq .
```

See [cli.md](../cli.md) and the [API reference](../api/README.md).
