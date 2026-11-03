// Package obs controls OBS Studio through obs-websocket v5 (built into OBS
// 28 and later): scenes, streaming, recording and audio inputs.
package obs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OBS connection's settings.
type Config struct {
	URL      string `json:"url"`      // ws://host:4455
	Password string `json:"password"` // secret://, empty when auth is off
}

type conn struct {
	cfg  Config
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the OBS module.
func New() *Module { return &Module{} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "obs", Name: "OBS Studio", Version: "0.1.0", Category: "Streaming", Icon: "video",
		Description: "Switch scenes, start and stop streams and recordings, and mute inputs in OBS Studio.",
		Presets:     []string{"gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","default":"ws://127.0.0.1:4455","description":"OBS: Tools, WebSocket Server Settings"},
			"password":{"type":"string","x-secret":true,"description":"The server password, if authentication is on"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Streaming, recording and the current scene.", Risk: sdk.RiskRead},
			{Name: "scenes", Title: "Scenes", Risk: sdk.RiskRead},
			{Name: "switch_scene", Title: "Switch scene", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["scene"],"properties":{"scene":{"type":"string"}}}`)},
			{Name: "start_stream", Title: "Start streaming", Risk: sdk.RiskWrite, Reversible: true},
			{Name: "stop_stream", Title: "Stop streaming", Description: "Ends the live broadcast.", Risk: sdk.RiskDestructive},
			{Name: "start_record", Title: "Start recording", Risk: sdk.RiskWrite, Reversible: true},
			{Name: "stop_record", Title: "Stop recording", Description: "Returns where the file was saved.", Risk: sdk.RiskWrite},
			{Name: "toggle_mute", Title: "Mute or unmute an input", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["input"],"properties":{"input":{"type":"string","description":"e.g. Mic/Aux"}}}`)},
			{Name: "set_volume", Title: "Set an input's volume", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["input","db"],"properties":{"input":{"type":"string"},"db":{"type":"number","minimum":-100,"maximum":26,"description":"Decibels; 0 is unchanged level"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.URL == "" {
		c.URL = "ws://127.0.0.1:4455"
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return errors.New("the address looks like ws://127.0.0.1:4455")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and use its secret:// reference")
	}
	m.set.Put(id, &conn{cfg: c, host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// session is one authenticated obs-websocket connection.
type session struct {
	ws *websocket.Conn
	n  int
}

type message struct {
	Op int             `json:"op"`
	D  json.RawMessage `json:"d"`
}

// Auth computes the obs-websocket v5 authentication string.
func Auth(password, salt, challenge string) string {
	s := sha256.Sum256([]byte(password + salt))
	secret := base64.StdEncoding.EncodeToString(s[:])
	a := sha256.Sum256([]byte(secret + challenge))
	return base64.StdEncoding.EncodeToString(a[:])
}

func (c *conn) dial(ctx context.Context) (*session, error) {
	ws, _, err := websocket.Dial(ctx, c.cfg.URL, &websocket.DialOptions{Subprotocols: []string{"obswebsocket.json"}})
	if err != nil {
		return nil, fmt.Errorf("reach OBS at %s: %w (is OBS running with the WebSocket server on?)", c.cfg.URL, err)
	}
	ws.SetReadLimit(4 << 20)
	s := &session{ws: ws}
	var hello struct {
		RPCVersion     int `json:"rpcVersion"`
		Authentication *struct {
			Challenge string `json:"challenge"`
			Salt      string `json:"salt"`
		} `json:"authentication"`
	}
	if err := s.expect(ctx, 0, &hello); err != nil {
		ws.CloseNow()
		return nil, err
	}
	ident := map[string]any{"rpcVersion": 1, "eventSubscriptions": 0}
	if hello.Authentication != nil {
		if c.cfg.Password == "" {
			ws.CloseNow()
			return nil, errors.New("OBS asks for a password; add it in the settings")
		}
		pw, err := c.host.Secret(ctx, c.cfg.Password)
		if err != nil {
			ws.CloseNow()
			return nil, err
		}
		ident["authentication"] = Auth(pw, hello.Authentication.Salt, hello.Authentication.Challenge)
	}
	if err := s.send(ctx, 1, ident); err != nil {
		ws.CloseNow()
		return nil, err
	}
	if err := s.expect(ctx, 2, nil); err != nil {
		ws.CloseNow()
		if websocket.CloseStatus(err) == 4009 {
			return nil, errors.New("OBS rejected the password")
		}
		return nil, err
	}
	return s, nil
}

func (s *session) send(ctx context.Context, op int, d any) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	out, _ := json.Marshal(message{Op: op, D: b})
	return s.ws.Write(ctx, websocket.MessageText, out)
}

// expect reads until a message with op arrives (skipping events).
func (s *session) expect(ctx context.Context, op int, out any) error {
	for {
		_, b, err := s.ws.Read(ctx)
		if err != nil {
			return err
		}
		var msg message
		if json.Unmarshal(b, &msg) != nil {
			continue
		}
		if msg.Op == op {
			if out != nil {
				return json.Unmarshal(msg.D, out)
			}
			return nil
		}
	}
}

// Error is a failed obs-websocket request.
type Error struct {
	Code    int
	Comment string
}

func (e *Error) Error() string {
	if e.Comment != "" {
		return "OBS: " + e.Comment
	}
	return fmt.Sprintf("OBS refused the request (code %d)", e.Code)
}

func (s *session) request(ctx context.Context, typ string, data, out any) error {
	s.n++
	var rb [4]byte
	_, _ = rand.Read(rb[:])
	id := fmt.Sprintf("%d-%s", s.n, hex.EncodeToString(rb[:]))
	req := map[string]any{"requestType": typ, "requestId": id}
	if data != nil {
		req["requestData"] = data
	}
	if err := s.send(ctx, 6, req); err != nil {
		return err
	}
	for {
		var res struct {
			RequestType   string `json:"requestType"`
			RequestID     string `json:"requestId"`
			RequestStatus struct {
				Result  bool   `json:"result"`
				Code    int    `json:"code"`
				Comment string `json:"comment"`
			} `json:"requestStatus"`
			ResponseData json.RawMessage `json:"responseData"`
		}
		if err := s.expect(ctx, 7, &res); err != nil {
			return err
		}
		if res.RequestID != id {
			continue
		}
		if !res.RequestStatus.Result {
			return &Error{Code: res.RequestStatus.Code, Comment: res.RequestStatus.Comment}
		}
		if out != nil && len(res.ResponseData) > 0 {
			return json.Unmarshal(res.ResponseData, out)
		}
		return nil
	}
}

func (c *conn) with(ctx context.Context, f func(*session) error) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer s.ws.Close(websocket.StatusNormalClosure, "")
	return f(s)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		OBSVersion string `json:"obsVersion"`
	}
	if err := c.with(ctx, func(s *session) error { return s.request(ctx, "GetVersion", nil, &v) }); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "OBS " + v.OBSVersion}
}

type outputStatus struct {
	OutputActive   bool   `json:"outputActive"`
	OutputTimecode string `json:"outputTimecode"`
	OutputPath     string `json:"outputPath"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Scene string   `json:"scene"`
		Input string   `json:"input"`
		DB    *float64 `json:"db"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	var res sdk.Result
	err = c.with(ctx, func(s *session) error {
		switch call.Action {
		case "status":
			var st, rec outputStatus
			var sc struct {
				SceneName string `json:"currentProgramSceneName"`
			}
			if err := s.request(ctx, "GetStreamStatus", nil, &st); err != nil {
				return err
			}
			if err := s.request(ctx, "GetRecordStatus", nil, &rec); err != nil {
				return err
			}
			if err := s.request(ctx, "GetCurrentProgramScene", nil, &sc); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]any{"streaming": st.OutputActive, "streamTime": st.OutputTimecode,
				"recording": rec.OutputActive, "recordTime": rec.OutputTimecode, "scene": sc.SceneName})
			return err

		case "scenes":
			var l struct {
				Current string `json:"currentProgramSceneName"`
				Scenes  []struct {
					Name string `json:"sceneName"`
				} `json:"scenes"`
			}
			if err := s.request(ctx, "GetSceneList", nil, &l); err != nil {
				return err
			}
			out := []map[string]any{}
			// OBS lists scenes bottom to top; show them as OBS's scene list does.
			for i := len(l.Scenes) - 1; i >= 0; i-- {
				out = append(out, map[string]any{"name": l.Scenes[i].Name, "current": l.Scenes[i].Name == l.Current})
			}
			res, err = sdk.JSON(out)
			return err

		case "switch_scene":
			if strings.TrimSpace(p.Scene) == "" {
				return errors.New("name the scene")
			}
			var cur struct {
				SceneName string `json:"currentProgramSceneName"`
			}
			if err := s.request(ctx, "GetCurrentProgramScene", nil, &cur); err != nil {
				return err
			}
			if call.DryRun {
				return nil
			}
			if err := s.request(ctx, "SetCurrentProgramScene", map[string]string{"sceneName": p.Scene}, nil); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]string{"scene": p.Scene, "previous": cur.SceneName})
			if cur.SceneName != "" && cur.SceneName != p.Scene {
				res.Undo = sdk.UndoWith("switch_scene", map[string]string{"scene": cur.SceneName}, "Switch back to "+cur.SceneName)
			}
			return err

		case "start_stream", "start_record":
			typ, undo, what := "StartStream", "stop_stream", "Stop streaming"
			if call.Action == "start_record" {
				typ, undo, what = "StartRecord", "stop_record", "Stop recording"
			}
			if err := s.request(ctx, typ, nil, nil); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]bool{"started": true})
			res.Undo = sdk.UndoWith(undo, map[string]any{}, what)
			return err

		case "stop_stream":
			if err := s.request(ctx, "StopStream", nil, nil); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]bool{"stopped": true})
			return err

		case "stop_record":
			var out struct {
				OutputPath string `json:"outputPath"`
			}
			if err := s.request(ctx, "StopRecord", nil, &out); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]any{"stopped": true, "file": out.OutputPath})
			return err

		case "toggle_mute":
			if p.Input == "" {
				return errors.New("name the input, e.g. Mic/Aux")
			}
			var out struct {
				Muted bool `json:"inputMuted"`
			}
			if err := s.request(ctx, "ToggleInputMute", map[string]string{"inputName": p.Input}, &out); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]any{"input": p.Input, "muted": out.Muted})
			res.Undo = sdk.UndoWith("toggle_mute", map[string]string{"input": p.Input}, "Toggle "+p.Input+" back")
			return err

		case "set_volume":
			if p.Input == "" || p.DB == nil || *p.DB < -100 || *p.DB > 26 {
				return errors.New("name the input and a level from -100 to 26 dB")
			}
			var cur struct {
				DB float64 `json:"inputVolumeDb"`
			}
			if err := s.request(ctx, "GetInputVolume", map[string]string{"inputName": p.Input}, &cur); err != nil {
				return err
			}
			if err := s.request(ctx, "SetInputVolume", map[string]any{"inputName": p.Input, "inputVolumeDb": *p.DB}, nil); err != nil {
				return err
			}
			res, err = sdk.JSON(map[string]any{"input": p.Input, "db": *p.DB, "previousDb": cur.DB})
			res.Undo = sdk.UndoWith("set_volume", map[string]any{"input": p.Input, "db": cur.DB}, fmt.Sprintf("Set %s back to %.1f dB", p.Input, cur.DB))
			return err
		}
		return sdk.ErrUnknownAction(call.Action)
	})
	return res, err
}
