package hub

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAdminConsole(t *testing.T) {
	h := newHarness(t, nil)
	root := h.signup("root@example.com") // the configured admin address
	alice := h.signup("alice@example.com")
	_, dev := pairDaemon(h, alice)
	h.do("PUT", "/v1/sync/notes", dev, map[string]any{"version": 0, "data": "ciphertext"}, 200)
	h.do("POST", "/v1/orgs", alice, map[string]string{"name": "Alice's org"}, 201)
	key := h.do("POST", "/v1/keys", root, map[string]any{"name": "ci", "scopes": []string{"orgs:read"}}, 201)["secret"].(string)

	// Only admin people.
	h.do("GET", "/v1/admin/stats", alice, nil, 403)
	h.do("GET", "/v1/admin/stats", key, nil, 403)
	h.do("GET", "/v1/admin/stats", "", nil, 401)
	st := h.do("GET", "/v1/admin/stats", root, nil, 200)
	if st["accounts"] != 2.0 || st["daemons"] != 1.0 || st["syncBlobs"] != 1.0 || st["orgs"] != 1.0 {
		t.Fatalf("stats %v", st)
	}
	list := h.do("GET", "/v1/admin/accounts?q=ALICE", root, nil, 200)
	items := list["items"].([]any)
	if list["total"] != 1.0 || len(items) != 1 {
		t.Fatalf("search %v", list)
	}
	a := items[0].(map[string]any)
	if a["email"] != "alice@example.com" || a["devices"] != 1.0 || a["lastSignInAt"] == "" {
		t.Fatalf("row %v", a)
	}
	if h.do("GET", "/v1/admin/accounts?q=%25", root, nil, 200)["total"] != 0.0 {
		t.Fatal("a % in the search must be matched literally")
	}
	id := a["id"].(string)

	// Switching off ends sessions, devices and keys, and blocks sign-in.
	h.do("POST", "/v1/admin/accounts/"+id+"/disable", root, nil, 200)
	h.do("GET", "/v1/me", alice, nil, 401)
	h.do("GET", "/v1/sync", dev, nil, 401)
	h.do("POST", "/v1/sessions", "", map[string]string{"email": "alice@example.com", "password": "correct horse battery"}, 403)
	if !waitMail(h, "alice@example.com", "was switched off") {
		t.Fatal("no email to the account")
	}
	h.do("POST", "/v1/admin/accounts/"+id+"/enable", root, nil, 200)
	alice = h.do("POST", "/v1/sessions", "", map[string]string{"email": "alice@example.com", "password": "correct horse battery"}, 200)["token"].(string)
	h.do("GET", "/v1/sync", dev, nil, 401) // devices stay revoked

	// Not yourself, and never the last admin.
	var rootID string
	_ = h.srv.db.Row(context.Background(), `SELECT id FROM accounts WHERE email = ?`, "root@example.com").Scan(&rootID)
	h.do("POST", "/v1/admin/accounts/"+rootID+"/disable", root, nil, 400)
	h.do("DELETE", "/v1/admin/accounts/"+rootID, root, nil, 400)
	_, _ = h.srv.db.Exec(context.Background(), `UPDATE accounts SET is_admin = 1 WHERE id = ?`, id)
	h.do("POST", "/v1/admin/accounts/"+rootID+"/disable", alice, nil, 200) // another admin exists
	h.do("GET", "/v1/me", root, nil, 401)
	h.do("POST", "/v1/admin/accounts/"+rootID+"/enable", alice, nil, 200)
	root = h.do("POST", "/v1/sessions", "", map[string]string{"email": "root@example.com", "password": "correct horse battery"}, 200)["token"].(string)
	_, _ = h.srv.db.Exec(context.Background(), `UPDATE accounts SET is_admin = 0 WHERE id = ?`, id)

	// Deleting removes everything the hub keeps for the account.
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	h.do("POST", "/v1/registry/authors", alice, map[string]string{"handle": "alice", "publicKey": pub}, 201)
	h.do("DELETE", "/v1/admin/accounts/"+id, root, nil, 204)
	// Its author handle stays taken, so nobody publishes under it.
	mallory := h.signup("mallory@example.com")
	h.do("POST", "/v1/registry/authors", mallory, map[string]string{"handle": "alice", "publicKey": pub}, 409)
	h.do("POST", "/v1/registry/authors", mallory, map[string]string{"handle": "mcp", "publicKey": pub}, 409)
	for _, tbl := range []string{"hub_sessions", "devices", "sync_blobs", "hub_keys", "org_members", "passkeys"} {
		var n int
		_ = h.srv.db.Row(context.Background(), `SELECT COUNT(*) FROM `+tbl+` WHERE account_id = ?`, id).Scan(&n)
		if n != 0 {
			t.Fatalf("%s still has %d rows", tbl, n)
		}
	}
	if h.do("GET", "/v1/admin/stats", root, nil, 200)["orgs"] != 0.0 {
		t.Fatal("an empty organisation was left behind")
	}
	h.do("POST", "/v1/sessions", "", map[string]string{"email": "alice@example.com", "password": "correct horse battery"}, 401)
}

func waitMail(h *harness, to, subject string) bool {
	for i := 0; i < 100; i++ {
		h.mail.mu.Lock()
		for _, m := range h.mail.sent {
			if strings.HasPrefix(m, to+"\n") && strings.Contains(m, subject) {
				h.mail.mu.Unlock()
				return true
			}
		}
		h.mail.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
