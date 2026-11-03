package obs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeOBS speaks enough obs-websocket v5 for the module: the handshake with
// authentication, and requests answered from in-memory state.
type fakeOBS struct {
	password  string
	mu        sync.Mutex
	scene     string
	streaming bool
	recording bool
	muted     map[string]bool
	volume    map[string]float64
}

func (f *fakeOBS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"obswebsocket.json"}})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ctx := r.Context()
	send := func(op int, d any) {
		b, _ := json.Marshal(d)
		out, _ := json.Marshal(message{Op: op, D: b})
		_ = ws.Write(ctx, websocket.MessageText, out)
	}
	hello := map[string]any{"obsWebSocketVersion": "5.5.0", "rpcVersion": 1}
	if f.password != "" {
		hello["authentication"] = map[string]string{"challenge": "chal", "salt": "salt"}
	}
	send(0, hello)
	_, b, err := ws.Read(ctx)
	if err != nil {
		return
	}
	var id struct {
		D struct {
			RPCVersion     int    `json:"rpcVersion"`
			Authentication string `json:"authentication"`
		} `json:"d"`
	}
	_ = json.Unmarshal(b, &id)
	if f.password != "" && id.D.Authentication != Auth(f.password, "salt", "chal") {
		ws.Close(4009, "Authentication failed.")
		return
	}
	send(2, map[string]int{"negotiatedRpcVersion": 1})
	// An event first, which the client must skip.
	send(5, map[string]string{"eventType": "CurrentProgramSceneChanged"})
	for {
		_, b, err := ws.Read(ctx)
		if err != nil {
			return
		}
		var req struct {
			D struct {
				Type string          `json:"requestType"`
				ID   string          `json:"requestId"`
				Data json.RawMessage `json:"requestData"`
			} `json:"d"`
		}
		_ = json.Unmarshal(b, &req)
		var in struct {
			Scene string  `json:"sceneName"`
			Input string  `json:"inputName"`
			DB    float64 `json:"inputVolumeDb"`
		}
		_ = json.Unmarshal(req.D.Data, &in)
		ok, comment := true, ""
		var data any
		f.mu.Lock()
		switch req.D.Type {
		case "GetVersion":
			data = map[string]string{"obsVersion": "31.0.0"}
		case "GetStreamStatus":
			data = map[string]any{"outputActive": f.streaming, "outputTimecode": "00:01:00.000"}
		case "GetRecordStatus":
			data = map[string]any{"outputActive": f.recording}
		case "GetCurrentProgramScene":
			data = map[string]string{"currentProgramSceneName": f.scene}
		case "GetSceneList":
			data = map[string]any{"currentProgramSceneName": f.scene, "scenes": []map[string]any{{"sceneName": "BRB"}, {"sceneName": "Game"}, {"sceneName": "Starting"}}}
		case "SetCurrentProgramScene":
			if in.Scene != "BRB" && in.Scene != "Game" && in.Scene != "Starting" {
				ok, comment = false, "No source was found by the name of `"+in.Scene+"`."
			} else {
				f.scene = in.Scene
			}
		case "StartStream":
			if f.streaming {
				ok, comment = false, "The stream output is already active."
			}
			f.streaming = true
		case "StopStream":
			f.streaming = false
		case "StartRecord":
			f.recording = true
		case "StopRecord":
			f.recording = false
			data = map[string]string{"outputPath": "/videos/2026-11-03.mkv"}
		case "ToggleInputMute":
			f.muted[in.Input] = !f.muted[in.Input]
			data = map[string]bool{"inputMuted": f.muted[in.Input]}
		case "GetInputVolume":
			data = map[string]float64{"inputVolumeDb": f.volume[in.Input]}
		case "SetInputVolume":
			f.volume[in.Input] = in.DB
		default:
			ok, comment = false, "unknown request"
		}
		f.mu.Unlock()
		// A response to someone else's request first, to check matching by id.
		send(7, map[string]any{"requestType": "Other", "requestId": "not-yours", "requestStatus": map[string]any{"result": true, "code": 100}})
		code := 100
		if !ok {
			code = 600
		}
		send(7, map[string]any{"requestType": req.D.Type, "requestId": req.D.ID, "requestStatus": map[string]any{"result": ok, "code": code, "comment": comment}, "responseData": data})
	}
}

func setup(t *testing.T, password, configured string) (*Module, *fakeOBS) {
	t.Helper()
	f := &fakeOBS{password: password, scene: "Starting", muted: map[string]bool{}, volume: map[string]float64{"Mic/Aux": -6}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg, _ := json.Marshal(Config{URL: "ws" + strings.TrimPrefix(srv.URL, "http"), Password: configured})
	host := fakehost.New(map[string]string{"secret://obs": "hunter22", "secret://wrong": "nope"})
	if err := m.Configure(context.Background(), host, "o", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(t *testing.T, m *Module, action, input string) sdk.Result {
	t.Helper()
	if input == "" {
		input = "{}"
	}
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(input)})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func TestOBS(t *testing.T) {
	m, f := setup(t, "hunter22", "secret://obs")
	ctx := context.Background()
	if h := m.Health(ctx, "o"); h.Status != "ok" || h.Message != "OBS 31.0.0" {
		t.Fatalf("health %+v", h)
	}
	var scenes []map[string]any
	_ = json.Unmarshal(call(t, m, "scenes", "").Output, &scenes)
	if len(scenes) != 3 || scenes[0]["name"] != "Starting" || scenes[0]["current"] != true {
		t.Fatalf("scenes %v", scenes)
	}

	r := call(t, m, "switch_scene", `{"scene":"Game"}`)
	if f.scene != "Game" || r.Undo == nil {
		t.Fatalf("switch: scene %s undo %v", f.scene, r.Undo)
	}
	call(t, m, r.Undo.Action, string(r.Undo.Input))
	if f.scene != "Starting" {
		t.Fatalf("undo switch: %s", f.scene)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "o", Action: "switch_scene", Input: json.RawMessage(`{"scene":"Nope"}`)}); err == nil || !strings.Contains(err.Error(), "Nope") {
		t.Fatalf("unknown scene: %v", err)
	}

	r = call(t, m, "start_stream", "")
	if !f.streaming || r.Undo.Action != "stop_stream" {
		t.Fatal("start stream")
	}
	var st map[string]any
	_ = json.Unmarshal(call(t, m, "status", "").Output, &st)
	if st["streaming"] != true || st["scene"] != "Starting" {
		t.Fatalf("status %v", st)
	}
	call(t, m, "stop_stream", "")
	if f.streaming {
		t.Fatal("stop stream")
	}

	call(t, m, "start_record", "")
	var rec map[string]any
	_ = json.Unmarshal(call(t, m, "stop_record", "").Output, &rec)
	if f.recording || rec["file"] != "/videos/2026-11-03.mkv" {
		t.Fatalf("record %v", rec)
	}

	r = call(t, m, "toggle_mute", `{"input":"Mic/Aux"}`)
	if !f.muted["Mic/Aux"] {
		t.Fatal("mute")
	}
	call(t, m, r.Undo.Action, string(r.Undo.Input))
	if f.muted["Mic/Aux"] {
		t.Fatal("unmute")
	}

	r = call(t, m, "set_volume", `{"input":"Mic/Aux","db":-20}`)
	if f.volume["Mic/Aux"] != -20 {
		t.Fatal("volume")
	}
	call(t, m, r.Undo.Action, string(r.Undo.Input))
	if f.volume["Mic/Aux"] != -6 {
		t.Fatalf("volume undo %v", f.volume["Mic/Aux"])
	}
}

func TestOBSAuth(t *testing.T) {
	m, _ := setup(t, "hunter22", "secret://wrong")
	if h := m.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "password") {
		t.Fatalf("wrong password: %+v", h)
	}
	m, _ = setup(t, "hunter22", "")
	if h := m.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "password") {
		t.Fatalf("no password: %+v", h)
	}
	m, _ = setup(t, "", "")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" {
		t.Fatalf("no auth: %+v", h)
	}
}

func TestOBSConfig(t *testing.T) {
	m := New()
	h := fakehost.New(nil)
	for _, c := range []string{`{"url":"http://x:4455"}`, `{"url":"ws://x:4455","password":"plain"}`} {
		if err := m.Configure(context.Background(), h, "o", json.RawMessage(c)); err == nil {
			t.Errorf("%s accepted", c)
		}
	}
}

// The authentication string from the obs-websocket protocol docs' method.
func TestAuthString(t *testing.T) {
	if Auth("supersecretpassword", "lM1GncleQOaCu9lT1yeUZhFYnqhsLLP1G5lAGo3ixaI=", "+IxH4CnCiqpX1rM9scsNynZzbOe4KhDeYcTNS3PDaeY=") !=
		"1Ct943GAT+6YQUUX47Ia/ncufilbe6+oD6lY+5kaCu4=" {
		t.Fatal("auth string doesn't match the protocol's example")
	}
}
