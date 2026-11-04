package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// account resolves the account id for account-level APIs: the configured
// one, or the only account the token can see.
func (a *account) account(ctx context.Context) (string, error) {
	if a.accountID != "" {
		return a.accountID, nil
	}
	var as []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := a.call(ctx, "GET", "/accounts", url.Values{"per_page": {"5"}}, nil, &as); err != nil {
		return "", err
	}
	switch {
	case len(as) == 0:
		return "", errors.New("the token can't see any account; give it Account: Cloudflare Tunnel: Read")
	case len(as) > 1:
		names := []string{}
		for _, x := range as {
			names = append(names, x.Name+" ("+x.ID+")")
		}
		return "", errors.New("the token sees several accounts; set the account ID in the settings: " + strings.Join(names, ", "))
	}
	if !accountRe.MatchString(as[0].ID) {
		return "", errors.New("unexpected account id from Cloudflare")
	}
	return as[0].ID, nil
}

// Tunnel is a tunnel row.
type Tunnel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"` // healthy, degraded, down, inactive
	Type        string `json:"type,omitempty"`
	Managed     string `json:"managed"` // dashboard or local
	Connections int    `json:"connections"`
	Colos       string `json:"edge,omitempty"`
	ActiveAt    string `json:"connectedAt,omitempty"`
	Created     string `json:"created,omitempty"`
}

type cfTunnel struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	TunType      string `json:"tun_type"`
	RemoteConfig bool   `json:"remote_config"`
	CreatedAt    string `json:"created_at"`
	ConnsActive  string `json:"conns_active_at"`
	Connections  []struct {
		Colo     string `json:"colo_name"`
		Pending  bool   `json:"is_pending_reconnect"`
		OriginIP string `json:"origin_ip"`
	} `json:"connections"`
}

func (t cfTunnel) row() Tunnel {
	colos := map[string]bool{}
	n := 0
	for _, c := range t.Connections {
		if !c.Pending {
			n++
		}
		if c.Colo != "" {
			colos[c.Colo] = true
		}
	}
	names := make([]string, 0, len(colos))
	for k := range colos {
		names = append(names, k)
	}
	sort.Strings(names)
	managed := "local"
	if t.RemoteConfig {
		managed = "dashboard"
	}
	return Tunnel{ID: t.ID, Name: t.Name, Status: t.Status, Type: t.TunType, Managed: managed, Connections: n,
		Colos: strings.Join(names, ", "), ActiveAt: t.ConnsActive, Created: t.CreatedAt}
}

func (a *account) listTunnels(ctx context.Context, acct string, name string) ([]cfTunnel, error) {
	q := url.Values{"is_deleted": {"false"}, "per_page": {"100"}}
	if name != "" {
		q.Set("name", name)
	}
	var ts []cfTunnel
	if err := a.call(ctx, "GET", "/accounts/"+acct+"/cfd_tunnel", q, nil, &ts); err != nil {
		if rest.IsStatus(err, 403) {
			return nil, errors.New("the token isn't allowed to read tunnels (add Account: Cloudflare Tunnel: Read)")
		}
		return nil, err
	}
	return ts, nil
}

// tunnels runs the tunnels and tunnel actions.
func (a *account) tunnels(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	var p struct {
		Tunnel string `json:"tunnel"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	if c.Action == "tunnel" {
		// Check the input before anything reaches the API.
		p.Tunnel = strings.TrimSpace(p.Tunnel)
		if p.Tunnel == "" || len(p.Tunnel) > 100 || strings.ContainsAny(p.Tunnel, "/?#%\\") {
			return sdk.Result{}, errors.New("enter the tunnel's name or id")
		}
	}
	acct, err := a.account(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if c.Action == "tunnels" {
		ts, err := a.listTunnels(ctx, acct, "")
		if err != nil {
			return sdk.Result{}, err
		}
		rank := map[string]int{"down": 0, "degraded": 1, "healthy": 2, "inactive": 3}
		out := []Tunnel{}
		for _, t := range ts {
			out = append(out, t.row())
		}
		sort.SliceStable(out, func(i, j int) bool {
			if rank[out[i].Status] != rank[out[j].Status] {
				return rank[out[i].Status] < rank[out[j].Status]
			}
			return out[i].Name < out[j].Name
		})
		return sdk.JSON(out)
	}

	var t cfTunnel
	if uuidRe.MatchString(strings.ToLower(p.Tunnel)) {
		if err := a.call(ctx, "GET", "/accounts/"+acct+"/cfd_tunnel/"+strings.ToLower(p.Tunnel), nil, nil, &t); err != nil {
			return sdk.Result{}, err
		}
	} else {
		ts, err := a.listTunnels(ctx, acct, p.Tunnel)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, x := range ts {
			if x.Name == p.Tunnel {
				t = x
			}
		}
		if t.ID == "" {
			return sdk.Result{}, fmt.Errorf("no tunnel named %s", p.Tunnel)
		}
	}
	if !uuidRe.MatchString(t.ID) {
		return sdk.Result{}, errors.New("unexpected tunnel id from Cloudflare")
	}
	var conns []struct {
		ID       string `json:"id"`
		Version  string `json:"version"`
		Arch     string `json:"arch"`
		RunAt    string `json:"run_at"`
		Features []any  `json:"features"`
		Conns    []struct {
			Colo     string `json:"colo_name"`
			OpenedAt string `json:"opened_at"`
			OriginIP string `json:"origin_ip"`
			Pending  bool   `json:"is_pending_reconnect"`
		} `json:"conns"`
	}
	if err := a.call(ctx, "GET", "/accounts/"+acct+"/cfd_tunnel/"+t.ID+"/connections", nil, nil, &conns); err != nil {
		return sdk.Result{}, err
	}
	connectors := []map[string]any{}
	for _, cn := range conns {
		edges := []map[string]any{}
		for _, e := range cn.Conns {
			edges = append(edges, map[string]any{"edge": e.Colo, "openedAt": e.OpenedAt, "originIp": e.OriginIP, "reconnecting": e.Pending})
		}
		connectors = append(connectors, map[string]any{"id": cn.ID, "version": cn.Version, "platform": cn.Arch, "startedAt": cn.RunAt, "connections": edges})
	}
	out := map[string]any{"tunnel": t.row(), "connectors": connectors}
	if t.RemoteConfig {
		var cfg struct {
			Config struct {
				Ingress []struct {
					Hostname string `json:"hostname"`
					Path     string `json:"path"`
					Service  string `json:"service"`
				} `json:"ingress"`
			} `json:"config"`
		}
		if err := a.call(ctx, "GET", "/accounts/"+acct+"/cfd_tunnel/"+t.ID+"/configurations", nil, nil, &cfg); err == nil {
			routes := []map[string]string{}
			for _, r := range cfg.Config.Ingress {
				routes = append(routes, map[string]string{"hostname": r.Hostname, "path": r.Path, "service": r.Service})
			}
			out["routes"] = routes
		} else {
			out["routes"] = json.RawMessage(`null`)
		}
	}
	return sdk.JSON(out)
}
