package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/wgnet"
)

func TestNetworksAPI(t *testing.T) {
	app, c, _, lampID := setup(t)
	if code := c.do("POST", "/api/v1/vault/setup", map[string]string{"passphrase": "a long vault passphrase"}, nil); code != 200 {
		t.Fatalf("vault setup = %d", code)
	}
	priv, _ := wgnet.GenerateKey()
	peerPriv, _ := wgnet.GenerateKey()
	peerPub, _ := wgnet.PublicKey(peerPriv)
	psk, _ := wgnet.GenerateKey()
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.90.0.2/32\nDNS = 10.90.0.1\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = 127.0.0.1:51999\nAllowedIPs = 10.90.0.0/24\n", priv, peerPub, psk)

	var raw map[string]any
	if code := c.do("POST", "/api/v1/networks", map[string]any{"name": "Forgejo LAN", "conf": conf}, &raw); code != 201 {
		t.Fatalf("create = %d %v", code, raw)
	}
	id, _ := raw["id"].(string)
	flat := fmt.Sprint(raw)
	if strings.Contains(flat, priv) || strings.Contains(flat, psk) {
		t.Fatal("key material in the response")
	}
	if raw["privateKey"] != "secret://networks/"+id+"/private-key" {
		t.Fatalf("private key ref %v", raw["privateKey"])
	}
	wantPub, _ := wgnet.PublicKey(priv)
	if raw["publicKey"] != wantPub {
		t.Fatalf("public key %v", raw["publicKey"])
	}
	if v, err := app.Vault.Resolve(t.Context(), "secret://networks/"+id+"/private-key"); err != nil || v != priv {
		t.Fatalf("vault: %v", err)
	}

	// The key can't be read back and the status shows the peer.
	var st wgnet.Status
	if code := c.do("GET", "/api/v1/networks/"+id+"/status", nil, &st); code != 200 || st.Running || len(st.Peers) != 1 {
		t.Fatalf("status = %d %+v", code, st)
	}

	// Rename keeps the key.
	var got wgnet.Config
	if code := c.do("PUT", "/api/v1/networks/"+id, map[string]any{"name": "Office", "addresses": []string{"10.90.0.2/32"},
		"peers": []map[string]any{{"publicKey": peerPub, "allowedIPs": []string{"10.90.0.0/24"}}}}, &got); code != 200 {
		t.Fatalf("update = %d", code)
	}
	if got.Name != "Office" || got.PrivateKey != "secret://networks/"+id+"/private-key" || got.Peers[0].PresharedKey != "" {
		t.Fatalf("updated %+v", got)
	}

	// Attach an instance; the network can't be deleted while it's used.
	var in core.Instance
	if code := c.do("PUT", "/api/v1/instances/"+lampID, map[string]any{"network": id}, &in); code != 200 || in.Network != id {
		t.Fatalf("attach = %d %+v", code, in)
	}
	if code := c.do("PUT", "/api/v1/instances/"+lampID, map[string]any{"network": "net_nope"}, nil); code != 400 {
		t.Fatalf("unknown network = %d", code)
	}
	if code := c.do("PUT", "/api/v1/instances/"+lampID, map[string]any{"name": "Lamp"}, &in); code != 200 || in.Network != id {
		t.Fatalf("a change without network keeps it: %d %+v", code, in)
	}
	if code := c.do("DELETE", "/api/v1/networks/"+id, nil, nil); code != 409 {
		t.Fatalf("delete while used = %d", code)
	}
	in = core.Instance{}
	if code := c.do("PUT", "/api/v1/instances/"+lampID, map[string]any{"network": ""}, &in); code != 200 || in.Network != "" {
		t.Fatalf("detach = %d %+v", code, in)
	}

	// Bad input.
	if code := c.do("POST", "/api/v1/networks", map[string]any{"name": "x", "conf": "[Interface]\nPrivateKey = nope\n"}, nil); code != 400 {
		t.Fatalf("bad conf = %d", code)
	}
	if code := c.do("POST", "/api/v1/networks", map[string]any{"name": "x"}, nil); code != 400 {
		t.Fatalf("no key = %d", code)
	}

	// A key may not create networks.
	var k createdKey
	c.do("POST", "/api/v1/keys", map[string]any{"name": "script", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	if k.Secret != "" {
		kc := client{t: t, base: c.base, token: k.Secret}
		if code := kc.do("POST", "/api/v1/networks", map[string]any{"name": "x", "generateKey": true}, nil); code != 403 {
			t.Fatalf("key create = %d", code)
		}
	}

	if code := c.do("DELETE", "/api/v1/networks/"+id, nil, nil); code != 204 {
		t.Fatalf("delete = %d", code)
	}
	if _, err := app.Vault.Resolve(t.Context(), "secret://networks/"+id+"/private-key"); err == nil {
		t.Fatal("the stored key should go with the network")
	}
	var audit []core.Entry
	c.do("GET", "/api/v1/audit?instance="+id, nil, &audit)
	acts := []string{}
	for _, e := range audit {
		acts = append(acts, e.Action)
		if strings.Contains(string(e.Input), priv) {
			t.Fatal("key in the audit log")
		}
	}
	if j := strings.Join(acts, ","); !strings.Contains(j, "network_created") || !strings.Contains(j, "network_deleted") {
		t.Fatalf("audit %v", acts)
	}
}
