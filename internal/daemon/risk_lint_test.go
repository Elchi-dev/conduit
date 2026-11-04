package daemon

import (
	"regexp"
	"sort"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// destructiveName matches action names that say they do something an agent
// approved only for write must not do: delete, stop or abort running work,
// run or ship code, apply infrastructure, move money, change access, blind
// monitoring, interrupt, cancel, suspend or pause running work, scale it to
// zero, or reveal a secret. A verb counts only as the whole name or its
// first word (stop, stop_build), so listings such as deployments or deploys
// don't match.
var destructiveName = regexp.MustCompile(`^(` +
	`deploy|redeploy|rollback|restart|stop|delete|remove|purge|drain|revoke|deactivate|` +
	`refund|apply|merge|approve|transfer|shutdown|reboot|poweroff|wipe|terminate|kill|` +
	`unseal|seal|dispatch|reveal|interrupt|abort|cancel|suspend|pause|scale_to_zero` +
	`)(_|$)|^(` +
	`cancel_build|cancel_run|stop_pipeline|disable_user|enable_client|activate_user|` +
	`set_secret|run_pipeline|trigger_build|trigger_deploy|queue_plan` +
	`)$|^scale(_[a-z]+)*_to_zero$`)

// riskLintAllow lists the genuine exceptions, as "module.action", each with
// why it isn't destructive. Keep it short: raising the risk is the default
// answer to a hit. Entries are keyed by name, so modules being added or
// reordered in builtins don't affect them.
var riskLintAllow = map[string]string{
	// Nouns, not verbs: read-only listings and records.
	"github.deploy_keys":    "read: lists a repository's deploy keys",
	"gitlab.merge_requests": "read: lists merge requests",
	"netlify.deploy":        "read: one deploy's status",
	"render.deploy":         "read: one deploy's status",
	"qbittorrent.transfer":  "read: transfer speeds and totals",

	// Media playback, nothing is lost or interrupted beyond what's playing.
	"kodi.stop":        "stops media playback on a player",
	"spotify.pause":    "pauses playback; undo resumes it",
	"spotify.transfer": "moves playback to another of the user's devices",

	// Pausing one monitor is write with an undo that resumes it (pausing all
	// of them isn't offered): it silences one check, it stops no work.
	"healthchecks.pause_check":  "pauses one check's alerts; undo resumes it",
	"uptimerobot.pause_monitor": "pauses one monitor; undo resumes it",

	// Pauses that lose nothing, stop no service anyone uses, and carry on
	// where they left off when the undo resumes them.
	"qbittorrent.pause":         "pauses downloads; undo resumes them where they were",
	"syncthing.pause":           "pauses syncing one folder or device; it catches up on resume (undo)",
	"unraid.pause_parity_check": "pauses the parity check; undo resumes it from where it was",
	"listmonk.pause_campaign":   "stops sending (it messages nobody); emails sent stay sent, and the undo, send_campaign, is destructive itself",

	// Cancels an operation that disrupts work, so it restores rather than stops.
	"nomad.cancel_drain": "ends a drain: the node takes work again, nothing running stops",

	// Metadata that's re-added as easily as it's removed (each has an undo).
	"github.remove_labels":    "removes labels from an issue; adding them is write too",
	"github.remove_reviewers": "withdraws review requests; it can't satisfy a required review",
	"paperless.remove_tag":    "untags documents; undo tags them again",
	"games.remove_custom":     "removes a hand-added game from the local list; play history stays",
}

// TestRiskLint fails when a built-in action whose name says it's destructive
// is declared below destructive and isn't a listed exception.
func TestRiskLint(t *testing.T) {
	seen := map[string]bool{}
	var hits []string
	for _, m := range builtins(&App{Server: &Server{}}) {
		mf := m.Manifest()
		for _, a := range mf.Actions {
			key := mf.ID + "." + a.Name
			if !destructiveName.MatchString(a.Name) {
				continue
			}
			if _, ok := riskLintAllow[key]; ok {
				seen[key] = true
				continue
			}
			if a.Risk != sdk.RiskDestructive {
				hits = append(hits, key+" is "+string(a.Risk))
			}
		}
	}
	sort.Strings(hits)
	for _, h := range hits {
		t.Errorf("%s: its name says destructive; raise its risk, or add it to riskLintAllow with a reason", h)
	}
	// An exception for an action that no longer exists (or no longer
	// matches) would hide a future one of the same name: drop stale entries.
	for key := range riskLintAllow {
		if !seen[key] {
			t.Errorf("riskLintAllow has %s, which isn't a matching built-in action any more", key)
		}
	}
}

func TestRiskLintPattern(t *testing.T) {
	for name, want := range map[string]bool{
		"stop": true, "stop_build": true, "delete_file": true, "redeploy": true, "queue_plan": true,
		"enable_client": true, "set_secret": true, "dispatch_workflow": true, "seal": true,
		"reveal": true, "reveal_secret": true, "revealed": false,
		"deployments": false, "deploys": false, "stopwatch": false, "set_secrets_note": false,
		"enable_workflow": false, "unmute_monitor": false,
		"interrupt": true, "abort_job": true, "cancel": true, "cancel_queued": true, "suspend_vm": true, "pause": true,
		"pause_monitor": true, "scale_to_zero": true, "scale_endpoint_to_zero": true, "interrupted": false, "paused": false, "unpause": false,
		"cancellations": false, "suspended_users": false, "resume": false,
	} {
		if got := destructiveName.MatchString(name); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// sensitiveUndo lists the sensitive actions that are reversible, as
// "module.action", with the action their undo calls. The engine keeps a
// sensitive action's undo token in the audit log only when that action
// isn't sensitive itself (its input is logged in the clear whenever it runs,
// so it carries no secret: a key to delete, a version number, a share id).
// An undo that would replay a secret value can't be kept, so such an action
// mustn't claim to be reversible. The engine also keeps a token holding
// nothing but an identifier ("id", "name", "names") when the action it calls
// is sensitive; those are listed in sensitiveUndoByID.
var sensitiveUndo = map[string]string{
	"chatwoot.add_note":          "delete_note",        // deletes the note it added, by number
	"consul.kv_create":           "kv_delete",          // deletes the key it created
	"firefly.create_transaction": "delete_transaction", // deletes the transaction it recorded, by id
	"freshdesk.add_note":         "delete_note",        // deletes the note it added, by number
	"hashivault.write_secret":    "restore_version",    // restores the version that was current
	"monica.add_note":            "delete_note",        // deletes the note it added, by number
	"nextcloud.share":            "unshare",            // removes the link by its id
	"zammad.add_note":            "delete_note",        // deletes the note it added, by number
}

// sensitiveUndoByID lists the entries of sensitiveUndo whose undo action is
// sensitive itself, which the engine keeps only because the token is
// {"id": …} alone, or record numbers ({"ticket": …, "note": …}) alone (see
// keepUndo in internal/core).
var sensitiveUndoByID = map[string]bool{
	"chatwoot.add_note":          true, // delete_note's preview quotes the note
	"firefly.create_transaction": true, // delete_transaction's preview shows the transaction
	"freshdesk.add_note":         true, // delete_note's preview quotes the note
	"monica.add_note":            true, // delete_note's preview quotes the note
	"zammad.add_note":            true, // delete_note's preview quotes the note
}

// TestSensitiveUndo fails when a sensitive action claims an undo the audit
// log can't keep.
func TestSensitiveUndo(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range builtins(&App{Server: &Server{}}) {
		mf := m.Manifest()
		specs := map[string]sdk.ActionSpec{}
		for _, a := range mf.Actions {
			specs[a.Name] = a
		}
		for _, a := range mf.Actions {
			if !a.Sensitive || !a.Reversible {
				continue
			}
			key := mf.ID + "." + a.Name
			undo, ok := sensitiveUndo[key]
			if !ok {
				t.Errorf("%s is sensitive and reversible: its undo would replay secret material, which the audit log doesn't keep. Drop Reversible (and any undo wording), or undo through a non-sensitive action and list it in sensitiveUndo", key)
				continue
			}
			seen[key] = true
			target, ok := specs[undo]
			switch {
			case !ok:
				t.Errorf("%s: its undo action %s doesn't exist", key, undo)
			case target.Sensitive && !sensitiveUndoByID[key]:
				t.Errorf("%s: its undo action %s is sensitive, so the engine drops the undo (unless its token is an id alone: list it in sensitiveUndoByID)", key, undo)
			case !target.Sensitive && sensitiveUndoByID[key]:
				t.Errorf("%s: its undo action %s isn't sensitive; drop it from sensitiveUndoByID", key, undo)
			}
		}
	}
	for key := range sensitiveUndo {
		if !seen[key] {
			t.Errorf("sensitiveUndo has %s, which isn't a sensitive reversible built-in action any more", key)
		}
	}
}
