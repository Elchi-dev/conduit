package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeNets struct{ dialed []string }

func (f *fakeNets) Dial(_ context.Context, id, network, addr string, _ func(netip.Addr) bool) (net.Conn, error) {
	f.dialed = append(f.dialed, id+" "+network+" "+addr)
	return nil, errors.New("fake")
}

type hostKeeper struct {
	sdk.Module
	host sdk.Host
}

func (h *hostKeeper) Configure(ctx context.Context, host sdk.Host, id string, cfg json.RawMessage) error {
	h.host = host
	return nil
}

func TestInstanceNetworkDial(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	e := NewEngine(store, nil)
	nets := &fakeNets{}
	e.SetNetworks(nets)
	hk := &hostKeeper{Module: &netProbe{}}
	if err := e.Register(hk); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SaveInstance(ctx, Instance{ID: "p1", Module: "probe", Enabled: true, Network: "net_a"}); err != nil {
		t.Fatal(err)
	}
	nh, ok := hk.host.(sdk.NetHost)
	if !ok || nh.Network() != "net_a" {
		t.Fatal("the host should report the instance's network")
	}
	_, _ = sdk.DialContext(hk.host)(ctx, "tcp", "10.0.0.5:22")
	if len(nets.dialed) != 1 || nets.dialed[0] != "net_a tcp 10.0.0.5:22" {
		t.Fatalf("dialed %v", nets.dialed)
	}
	// The network survives a restart of the engine.
	e2 := NewEngine(store, nil)
	_ = e2.Register(&hostKeeper{Module: &netProbe{}})
	if err := e2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if in, _ := e2.Instance("p1"); in.Network != "net_a" {
		t.Fatalf("reloaded %+v", in)
	}
	if tr := sdk.Transport(hk.host); tr.Proxy != nil {
		t.Fatal("no environment proxy on a network")
	}
}

type netProbe struct{}

func (netProbe) Manifest() sdk.Manifest { return sdk.Manifest{ID: "probe", Name: "Probe"} }
func (netProbe) Configure(context.Context, sdk.Host, string, json.RawMessage) error {
	return nil
}
func (netProbe) Invoke(context.Context, sdk.Call) (sdk.Result, error) { return sdk.Result{}, nil }
func (netProbe) Health(context.Context, string) sdk.Health            { return sdk.Health{Status: "ok"} }
func (netProbe) Close(string) error                                   { return nil }
