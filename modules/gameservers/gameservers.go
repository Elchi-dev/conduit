// Package gameservers checks and runs the game servers you host: Minecraft
// (Java edition, Server List Ping and RCON) and Source/Valve games (A2S
// queries over UDP and Source RCON).
package gameservers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Server is one game server.
type Server struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"` // minecraft | source
	Host         string `json:"host"`
	Port         int    `json:"port"`         // game/query port; default 25565 or 27015
	RCONPort     int    `json:"rconPort"`     // default 25575 (minecraft) or the game port (source)
	RCONPassword string `json:"rconPassword"` // secret://
}

// Config is one instance's settings: a list of servers, or one server given
// directly.
type Config struct {
	Servers []Server `json:"servers"`
	Server
}

type conn struct {
	servers map[string]Server
	order   []string
	host    sdk.Host
}

// Module implements sdk.Module.
type Module struct{ set inst.Set[conn] }

// New returns the game servers module.
func New() *Module { return &Module{} }

var (
	hostRe   = regexp.MustCompile(`^[A-Za-z0-9.\-:\[\]]{1,253}$`)
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9 ._\-]{1,40}$`)
	playerRe = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
)

const srv = `"server":{"type":"string","description":"Server name; may be left out when there is only one"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "gameservers", Name: "Game servers", Version: "0.1.0", Category: "Gaming", Icon: "gamepad",
		Description: "See who's on your Minecraft and Source game servers, and run console commands.",
		Presets:     []string{"gamer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"servers":{"type":"array","items":{"type":"object","required":["kind","host"],"properties":{
				"name":{"type":"string"},
				"kind":{"type":"string","enum":["minecraft","source"],"description":"Minecraft Java edition, or a Source/Valve game (CS2, TF2, Garry's Mod, Rust, Valheim with A2S…)"},
				"host":{"type":"string"},
				"port":{"type":"integer","description":"Game or query port (25565 / 27015)"},
				"rconPort":{"type":"integer","description":"RCON port (Minecraft 25575; Source uses the game port)"},
				"rconPassword":{"type":"string","x-secret":true,"description":"For commands; leave empty to only watch the server"}}}}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Server status", Description: "Online, players, version and map or message of the day, for one server or all.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + srv + `}}`)},
			{Name: "players", Title: "Who's playing", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","properties":{` + srv + `}}`)},
			{Name: "say", Title: "Message everyone", Description: "Shown in the game chat.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["message"],"properties":{` + srv + `,"message":{"type":"string","maxLength":200}}}`)},
			{Name: "command", Title: "Run a console command", Description: "Anything the server console accepts, through RCON. It can't be undone.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["command"],"properties":{` + srv + `,"command":{"type":"string","maxLength":500}}}`)},
			{Name: "whitelist_add", Title: "Add to the whitelist", Description: "Minecraft only.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["player"],"properties":{` + srv + `,"player":{"type":"string"}}}`)},
			{Name: "whitelist_remove", Title: "Remove from the whitelist", Description: "Minecraft only.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["player"],"properties":{` + srv + `,"player":{"type":"string"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	list := c.Servers
	if len(list) == 0 && c.Host != "" {
		list = []Server{c.Server}
	}
	if len(list) == 0 {
		return errors.New("add at least one server")
	}
	cn := &conn{servers: map[string]Server{}, host: h}
	for i, s := range list {
		if s.Kind != "minecraft" && s.Kind != "source" {
			return fmt.Errorf("server %d: the kind is minecraft or source", i+1)
		}
		if !hostRe.MatchString(s.Host) || strings.Contains(s.Host, "://") {
			return fmt.Errorf("server %d: the host is a name or address, without http://", i+1)
		}
		if s.Port == 0 {
			s.Port = map[string]int{"minecraft": 25565, "source": 27015}[s.Kind]
		}
		if s.RCONPort == 0 {
			s.RCONPort = map[string]int{"minecraft": 25575, "source": s.Port}[s.Kind]
		}
		if s.Port < 1 || s.Port > 65535 || s.RCONPort < 1 || s.RCONPort > 65535 {
			return fmt.Errorf("server %d: ports are 1 to 65535", i+1)
		}
		if s.RCONPassword != "" && !strings.HasPrefix(s.RCONPassword, "secret://") {
			return fmt.Errorf("server %d: store the RCON password in the vault and enter its secret:// reference", i+1)
		}
		if s.Name == "" {
			s.Name = s.Host
		}
		if !nameRe.MatchString(s.Name) {
			return fmt.Errorf("server %d: names are letters, digits, spaces, dots and dashes", i+1)
		}
		if _, dup := cn.servers[s.Name]; dup {
			return fmt.Errorf("two servers are named %q", s.Name)
		}
		cn.servers[s.Name] = s
		cn.order = append(cn.order, s.Name)
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module: down when no server answers.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	up := 0
	for _, n := range c.order {
		if st := status(ctx, c.servers[n]); st.Online {
			up++
		}
	}
	switch {
	case up == len(c.order):
		return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d online", up)}
	case up == 0:
		return sdk.Health{Status: "down", Message: "no server answers"}
	default:
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d of %d online", up, len(c.order))}
	}
}

// Status is one server's state.
type Status struct {
	Server     string `json:"server"`
	Kind       string `json:"kind"`
	Online     bool   `json:"online"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"maxPlayers"`
	Version    string `json:"version,omitempty"`
	Name       string `json:"name,omitempty"` // MOTD or server name
	Map        string `json:"map,omitempty"`
	Game       string `json:"game,omitempty"`
	LatencyMS  int64  `json:"latencyMs,omitempty"`
	Error      string `json:"error,omitempty"`
}

func status(ctx context.Context, s Server) Status {
	st := Status{Server: s.Name, Kind: s.Kind}
	switch s.Kind {
	case "minecraft":
		mc, rtt, err := minecraftPing(ctx, s.Host, s.Port)
		if err != nil {
			st.Error = err.Error()
			return st
		}
		st.Online, st.Players, st.MaxPlayers, st.Version, st.Name = true, mc.Players.Online, mc.Players.Max, mc.Version.Name, mc.motd()
		st.LatencyMS = rtt.Milliseconds()
	case "source":
		in, rtt, err := sourceInfo(ctx, s.Host, s.Port)
		if err != nil {
			st.Error = err.Error()
			return st
		}
		st.Online, st.Players, st.MaxPlayers, st.Version, st.Name, st.Map, st.Game = true, in.Players, in.MaxPlayers, in.Version, in.Name, in.Map, in.Game
		st.LatencyMS = rtt.Milliseconds()
	}
	return st
}

func (c *conn) pick(name string) (Server, error) {
	if name == "" {
		if len(c.order) == 1 {
			return c.servers[c.order[0]], nil
		}
		return Server{}, errors.New("name the server: " + strings.Join(c.order, ", "))
	}
	s, ok := c.servers[name]
	if !ok {
		return Server{}, fmt.Errorf("no server named %q", name)
	}
	return s, nil
}

func (c *conn) rcon(ctx context.Context, s Server, command string) (string, error) {
	if s.RCONPassword == "" {
		return "", fmt.Errorf("%s has no RCON password in the settings", s.Name)
	}
	pw, err := c.host.Secret(ctx, s.RCONPassword)
	if err != nil {
		return "", err
	}
	return rcon(ctx, s.Host, s.RCONPort, pw, command)
}

func oneLine(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") }

// checkSay vets the text of a `say` message before it is spliced into an RCON
// command. `say` is a narrower action than `command`, so the text must not be
// able to break out of the say and run something else.
//
// Source (SRCDS) splits the console line on `;` outside double quotes, so
// `say hi; quit` would run quit; a `"` would let the text open or close a quoted
// span and defeat the rule. Minecraft runs one command per RCON packet, but
// control characters and the `§` formatting prefix are still refused there so
// the message is plain chat text.
func checkSay(kind, msg string) error {
	if msg == "" || len(msg) > 200 || !oneLine(msg) {
		return errors.New("a message is one line of 1 to 200 characters")
	}
	for _, r := range msg {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return errors.New("a message may not contain control characters")
		}
	}
	switch kind {
	case "source":
		if strings.ContainsAny(msg, ";\"") {
			return errors.New(`a message to a Source server may not contain ; or " (they would let it run other console commands); use the command action for that`)
		}
	case "minecraft":
		if strings.ContainsRune(msg, '§') {
			return errors.New("a message may not contain the § formatting character")
		}
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Server  string `json:"server"`
		Message string `json:"message"`
		Command string `json:"command"`
		Player  string `json:"player"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch call.Action {
	case "status":
		if p.Server == "" {
			out := []Status{}
			for _, n := range c.order {
				out = append(out, status(ctx, c.servers[n]))
			}
			return sdk.JSON(out)
		}
		s, err := c.pick(p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(status(ctx, s))

	case "players":
		s, err := c.pick(p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		if s.Kind == "minecraft" {
			mc, _, err := minecraftPing(ctx, s.Host, s.Port)
			if err != nil {
				return sdk.Result{}, err
			}
			names := []string{}
			for _, x := range mc.Players.Sample {
				names = append(names, x.Name)
			}
			// The server lists at most a sample of online players.
			return sdk.JSON(map[string]any{"online": mc.Players.Online, "max": mc.Players.Max, "names": names})
		}
		pl, err := sourcePlayers(ctx, s.Host, s.Port)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"online": len(pl), "players": pl})

	case "say":
		s, err := c.pick(p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		msg := strings.TrimSpace(p.Message)
		if err := checkSay(s.Kind, msg); err != nil {
			return sdk.Result{}, err
		}
		out, err := c.rcon(ctx, s, "say "+msg)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"server": s.Name, "answer": out})

	case "command":
		s, err := c.pick(p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		cmd := strings.TrimSpace(p.Command)
		if cmd == "" || len(cmd) > 500 || !oneLine(cmd) {
			return sdk.Result{}, errors.New("a command is one line of up to 500 characters")
		}
		out, err := c.rcon(ctx, s, cmd)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"server": s.Name, "answer": out})

	case "whitelist_add", "whitelist_remove":
		s, err := c.pick(p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		if s.Kind != "minecraft" {
			return sdk.Result{}, errors.New("the whitelist is a Minecraft feature")
		}
		if !playerRe.MatchString(p.Player) {
			return sdk.Result{}, errors.New("Minecraft names are 3 to 16 letters, digits or underscores")
		}
		verb, undo, desc := "add", "whitelist_remove", "Take "+p.Player+" off the whitelist again"
		if call.Action == "whitelist_remove" {
			verb, undo, desc = "remove", "whitelist_add", "Put "+p.Player+" back on the whitelist"
		}
		out, err := c.rcon(ctx, s, "whitelist "+verb+" "+p.Player)
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"server": s.Name, "answer": out})
		r.Undo = sdk.UndoWith(undo, map[string]string{"server": s.Name, "player": p.Player}, desc)
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
