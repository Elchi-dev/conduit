package gameservers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeMinecraft answers Server List Ping requests.
func fakeMinecraft(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for i := 0; i < 2; i++ { // handshake, then status request
					n, err := readVarint(r)
					if err != nil {
						return
					}
					if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
						return
					}
				}
				js := `{"version":{"name":"1.21.4","protocol":769},"players":{"max":20,"online":2,"sample":[{"name":"Steve","id":"x"},{"name":"Alex","id":"y"}]},"description":{"text":"Our ","extra":[{"text":"world"}]}}`
				var p bytes.Buffer
				putString(&p, js)
				_, _ = c.Write(packet(0, p.Bytes()))
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// fakeRCON implements Source RCON, recording commands.
type fakeRCON struct {
	mu       sync.Mutex
	commands []string
}

func (f *fakeRCON) start(t *testing.T, password string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					id, typ, body, err := readRCON(r)
					if err != nil {
						return
					}
					switch typ {
					case rconAuth:
						_ = writeRCON(c, id, rconResponse, "") // Source sends this first
						if body != password {
							id = -1
						}
						_ = writeRCON(c, id, rconAuthResponse, "")
					case rconExec:
						f.mu.Lock()
						f.commands = append(f.commands, body)
						f.mu.Unlock()
						_ = writeRCON(c, id, rconResponse, "ok: "+body)
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// fakeSource answers A2S_INFO and A2S_PLAYER, insisting on a challenge.
func fakeSource(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	challenge := []byte{1, 2, 3, 4}
	go func() {
		buf := make([]byte, 1400)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			p := buf[:n]
			var out bytes.Buffer
			out.Write(header)
			switch {
			case n >= 5 && p[4] == 'T':
				if !bytes.HasSuffix(p, challenge) {
					out.WriteByte(0x41)
					out.Write(challenge)
					break
				}
				out.WriteByte(0x49)
				out.WriteByte(17)
				for _, s := range []string{"Friday Night CS", "de_dust2", "cs2", "Counter-Strike 2"} {
					out.WriteString(s)
					out.WriteByte(0)
				}
				out.Write([]byte{0xDA, 0x02, 7, 10, 1, 'd', 'l', 0, 1})
				out.WriteString("1.40.1.0")
				out.WriteByte(0)
			case n >= 5 && p[4] == 'U':
				if !bytes.Equal(p[5:9], challenge) {
					out.WriteByte(0x41)
					out.Write(challenge)
					break
				}
				out.WriteByte(0x44)
				out.WriteByte(1)
				out.WriteByte(0)
				out.WriteString("gabe")
				out.WriteByte(0)
				_ = binary.Write(&out, binary.LittleEndian, int32(12))
				_ = binary.Write(&out, binary.LittleEndian, math.Float32bits(61.5))
			default:
				continue
			}
			_, _ = pc.WriteTo(out.Bytes(), addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestGameServers(t *testing.T) {
	ctx := context.Background()
	mcPort := fakeMinecraft(t)
	rc := &fakeRCON{}
	rconPort := rc.start(t, "hunter2")
	srcPort := fakeSource(t)

	m := New()
	h := fakehost.New(map[string]string{"secret://mc-rcon": "hunter2", "secret://bad": "nope"})
	cfg, _ := json.Marshal(Config{Servers: []Server{
		{Name: "survival", Kind: "minecraft", Host: "127.0.0.1", Port: mcPort, RCONPort: rconPort, RCONPassword: "secret://mc-rcon"},
		{Name: "cs", Kind: "source", Host: "127.0.0.1", Port: srcPort},
	}})
	if err := m.Configure(ctx, h, "g", cfg); err != nil {
		t.Fatal(err)
	}
	call := func(action, input string) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(input)})
	}

	r, err := call("status", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	var sts []Status
	_ = json.Unmarshal(r.Output, &sts)
	if len(sts) != 2 || !sts[0].Online || sts[0].Players != 2 || sts[0].Name != "Our world" || sts[0].Version != "1.21.4" {
		t.Fatalf("minecraft status %+v", sts)
	}
	if !sts[1].Online || sts[1].Map != "de_dust2" || sts[1].Players != 7 || sts[1].MaxPlayers != 10 || sts[1].Version != "1.40.1.0" {
		t.Fatalf("source status %+v", sts[1])
	}

	r, err = call("players", `{"server":"cs"}`)
	if err != nil || !strings.Contains(string(r.Output), `"gabe"`) || !strings.Contains(string(r.Output), `61.5`) {
		t.Fatalf("source players %s %v", r.Output, err)
	}
	r, err = call("players", `{"server":"survival"}`)
	if err != nil || !strings.Contains(string(r.Output), `"Steve"`) {
		t.Fatalf("minecraft players %s %v", r.Output, err)
	}
	if _, err := call("players", `{}`); err == nil {
		t.Fatal("ambiguous server accepted")
	}

	r, err = call("whitelist_add", `{"server":"survival","player":"Notch"}`)
	if err != nil || r.Undo == nil || r.Undo.Action != "whitelist_remove" {
		t.Fatalf("whitelist %v %+v", err, r.Undo)
	}
	if _, err := call(r.Undo.Action, string(r.Undo.Input)); err != nil {
		t.Fatal(err)
	}
	if _, err := call("say", `{"server":"survival","message":"Restart in 5 minutes"}`); err != nil {
		t.Fatal(err)
	}
	rc.mu.Lock()
	got := strings.Join(rc.commands, "|")
	rc.mu.Unlock()
	if got != "whitelist add Notch|whitelist remove Notch|say Restart in 5 minutes" {
		t.Fatalf("commands %q", got)
	}

	// Refusals.
	for _, bad := range []string{
		`{"server":"survival","player":"no spaces"}`,
		`{"server":"cs","player":"Notch"}`,
	} {
		if _, err := call("whitelist_add", bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, err := call("command", `{"server":"survival","command":"stop\nop me"}`); err == nil {
		t.Fatal("multi-line command accepted")
	}
	if _, err := call("command", `{"server":"cs","command":"status"}`); err == nil {
		t.Fatal("command without an RCON password accepted")
	}

	// A wrong RCON password is reported plainly.
	cfg2, _ := json.Marshal(Config{Server: Server{Kind: "minecraft", Host: "127.0.0.1", Port: mcPort, RCONPort: rconPort, RCONPassword: "secret://bad"}})
	_ = m.Configure(ctx, h, "g2", cfg2)
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "g2", Action: "command", Input: json.RawMessage(`{"command":"list"}`)}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("bad password: %v", err)
	}

	if h := m.Health(ctx, "g"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	for _, bad := range []string{
		`{}`,
		`{"servers":[{"kind":"quake","host":"x"}]}`,
		`{"kind":"minecraft","host":"http://x"}`,
		`{"kind":"minecraft","host":"x","rconPassword":"plaintext"}`,
	} {
		if err := m.Configure(ctx, h, "bad", json.RawMessage(bad)); err == nil {
			t.Fatalf("accepted settings %s", bad)
		}
	}
}

func TestVarint(t *testing.T) {
	for _, v := range []int32{0, 1, 127, 128, 255, 25565, 2097151, -1} {
		var b bytes.Buffer
		putVarint(&b, v)
		got, err := readVarint(&b)
		if err != nil || got != v {
			t.Fatalf("%d -> %d %v", v, got, err)
		}
	}
}

func TestSayCannotChainCommands(t *testing.T) {
	ctx := context.Background()
	rc := &fakeRCON{}
	rconPort := rc.start(t, "hunter2")
	m := New()
	h := fakehost.New(map[string]string{"secret://rc": "hunter2"})
	cfg, _ := json.Marshal(Config{Servers: []Server{
		{Name: "cs", Kind: "source", Host: "127.0.0.1", Port: 27015, RCONPort: rconPort, RCONPassword: "secret://rc"},
		{Name: "mc", Kind: "minecraft", Host: "127.0.0.1", Port: 25565, RCONPort: rconPort, RCONPassword: "secret://rc"},
	}})
	if err := m.Configure(ctx, h, "g", cfg); err != nil {
		t.Fatal(err)
	}
	say := func(server, msg string) error {
		in, _ := json.Marshal(map[string]string{"server": server, "message": msg})
		_, err := m.Invoke(ctx, sdk.Call{Instance: "g", Action: "say", Input: in})
		return err
	}
	for _, bad := range []string{"hi; quit", "hi;quit", `hi" ; "quit`, `"`, "a\x1b[2Jb", "tab\there", "x\u0085y"} {
		if err := say("cs", bad); err == nil {
			t.Fatalf("source say accepted %q", bad)
		}
	}
	for _, bad := range []string{"line\nop me", "a\x00b", "\u00a7kobfuscated", "a\x1bb"} {
		if err := say("mc", bad); err == nil {
			t.Fatalf("minecraft say accepted %q", bad)
		}
	}
	if err := say("cs", "Map change in 5 minutes, gg!"); err != nil {
		t.Fatal(err)
	}
	if err := say("mc", "Restart; back soon"); err != nil { // one command per packet on Minecraft
		t.Fatal(err)
	}
	rc.mu.Lock()
	got := strings.Join(rc.commands, "|")
	rc.mu.Unlock()
	if got != "say Map change in 5 minutes, gg!|say Restart; back soon" {
		t.Fatalf("commands %q", got)
	}
}
