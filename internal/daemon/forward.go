package daemon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

var systemActor = core.Actor{ID: "conduit", Kind: core.ActorSystem, Name: "Conduit"}

// forwardAlerts sends approval requests and emergency stops to every
// notification channel that asked for approvals, so people can act from
// their phone.
func forwardAlerts(ctx context.Context, app *App) {
	events, stop := app.Engine.Bus.Subscribe("", 256)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			var note map[string]string
			switch ev.Type {
			case "approval.requested":
				var a core.Approval
				if json.Unmarshal(ev.Data, &a) != nil {
					continue
				}
				who := a.Actor.Name
				if who == "" {
					who = a.Actor.Subject()
				}
				note = map[string]string{
					"title":    "Approval needed",
					"message":  fmt.Sprintf("%s wants to run %s on %s (%s risk).", who, a.Action, a.Module, a.Risk),
					"priority": "high",
					"path":     "/approvals",
				}
			case "panic.on":
				note = map[string]string{"title": "Emergency stop", "message": "Emergency stop was pulled. Agents, keys and automations are frozen.", "priority": "urgent", "path": "/policy"}
			default:
				continue
			}
			for _, in := range app.Engine.Instances("notify") {
				if !in.Enabled || !app.Notify.ForwardsApprovals(in.ID) {
					continue
				}
				n := map[string]string{"title": note["title"], "message": note["message"], "priority": note["priority"]}
				if base := app.Notify.AppURL(in.ID); base != "" {
					n["link"] = base + note["path"]
				}
				input, _ := json.Marshal(n)
				if _, err := app.Engine.Invoke(ctx, systemActor, sdk.Call{Instance: in.ID, Action: "send", Input: input}, core.InvokeOptions{NoWait: true}); err != nil {
					app.Engine.Log.Warn("could not forward alert", "channel", in.Name, "err", err)
				}
			}
		}
	}
}
