package zigbee2mqtt

import (
	"encoding/json"
	"strings"
	"testing"
)

// Real expose shapes (zigbee-herdsman-converters) of devices whose dangerous
// feature isn't under a lock, cover or climate expose.
const critDevices = `[
 {"ieee_address":"0x00124b0000000001","type":"Coordinator","friendly_name":"Coordinator","supported":true,"interview_completed":true,"definition":null},
 {"ieee_address":"0x00000000000000a1","type":"EndDevice","friendly_name":"Front door","supported":true,"interview_completed":true,
  "definition":{"model":"YRD226","vendor":"Yale","description":"Lock","exposes":[
   {"type":"lock","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"LOCK","value_off":"UNLOCK"}]},
   {"type":"composite","name":"pin_code","property":"pin_code","access":7,"features":[
     {"type":"numeric","name":"user","property":"user","access":2},
     {"type":"numeric","name":"pin_code","property":"pin_code","access":2}]},
   {"type":"binary","name":"auto_relock","property":"auto_relock","access":7,"value_on":true,"value_off":false}]}},
 {"ieee_address":"0x00000000000000a2","type":"Router","friendly_name":"Garage","supported":true,"interview_completed":true,
  "definition":{"model":"TS0601_garage_door_opener","vendor":"Tuya","description":"Garage door opener","exposes":[
   {"type":"binary","name":"trigger","property":"trigger","access":3,"value_on":true,"value_off":false}]}},
 {"ieee_address":"0x00000000000000a3","type":"EndDevice","friendly_name":"Smoke","supported":true,"interview_completed":true,
  "definition":{"model":"TS0601_smoke","vendor":"Tuya","description":"Smoke detector","exposes":[
   {"type":"binary","name":"smoke","property":"smoke","access":1,"value_on":true,"value_off":false},
   {"type":"binary","name":"silence","property":"silence","access":3,"value_on":true,"value_off":false}]}},
 {"ieee_address":"0x00000000000000a4","type":"Router","friendly_name":"Main","supported":true,"interview_completed":true,
  "definition":{"model":"SWV","vendor":"SONOFF","description":"Zigbee smart water valve","exposes":[
   {"type":"switch","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"ON","value_off":"OFF"}]}]}},
 {"ieee_address":"0x00000000000000a5","type":"EndDevice","friendly_name":"Keypad","supported":true,"interview_completed":true,
  "definition":{"model":"3400-D","vendor":"Centralite","description":"3-Series security keypad","exposes":[
   {"type":"composite","name":"arm_mode","property":"arm_mode","access":3,"features":[
     {"type":"enum","name":"mode","property":"mode","access":2,"values":["disarm","arm_all_zones"]}]}]}},
 {"ieee_address":"0x00000000000000a6","type":"Router","friendly_name":"Outdoor plug","supported":true,"interview_completed":true,
  "definition":{"model":"TS011F","vendor":"Tuya","description":"Smart plug","exposes":[
   {"type":"switch","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"ON","value_off":"OFF"}]},
   {"type":"enum","name":"power_on_behavior","property":"power_on_behavior","access":7,"values":["off","on","previous"]}]}},
 {"ieee_address":"0x00000000000000a7","type":"Router","friendly_name":"Gate relay","supported":true,"interview_completed":true,
  "definition":{"model":"ZBMINI","vendor":"SONOFF","description":"Zigbee two way smart switch","exposes":[
   {"type":"switch","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"ON","value_off":"OFF"}]}]}},
 {"ieee_address":"0x00000000000000a8","type":"Router","friendly_name":"Strip","supported":true,"interview_completed":true,
  "definition":{"model":"LED","vendor":"Gledopto","description":"LED strip","exposes":[
   {"type":"light","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"ON","value_off":"OFF"}]},
   {"type":"enum","name":"effect","property":"effect","access":2,"values":["blink","none"]},
   {"type":"binary","name":"state","property":"state","access":1,"value_on":"ON","value_off":"OFF"},
   {"type":"binary","name":"alarm","property":"state","access":1,"value_on":"ON","value_off":"OFF"}]}},
 {"ieee_address":"0x00000000000000a9","type":"Router","friendly_name":"Tap","supported":true,"interview_completed":true,
  "definition":{"model":"X","vendor":"Y","description":"Irrigation controller","exposes":[
   {"type":"valve","features":[{"type":"binary","name":"state","property":"state","access":7,"value_on":"OPEN","value_off":"CLOSED"}]}]}}
]`

func TestZ2MDefaultDeny(t *testing.T) {
	m, f := setup(t, nil)
	f.srv.Publish("zigbee2mqtt/bridge/devices", []byte(critDevices), true, 0)
	for _, in := range []string{
		`{"device":"Front door","payload":{"pin_code":{"user":7,"pin_code":4242}}}`,
		`{"device":"Front door","payload":{"auto_relock":false}}`,
		`{"device":"Garage","payload":{"trigger":true}}`,
		`{"device":"Smoke","payload":{"silence":true}}`,
		`{"device":"Main","payload":{"state":"OFF"}}`, // a valve behind a switch expose
		`{"device":"Keypad","payload":{"arm_mode":{"mode":"disarm"}}}`,
		`{"device":"Gate relay","payload":{"state":"ON"}}`,                // switch named for a gate
		`{"device":"Outdoor plug","payload":{"power_on_behavior":"off"}}`, // not a light/switch/fan property
		`{"device":"Strip","payload":{"state":"OFF"}}`,                    // a colliding critical twin makes it critical
		`{"device":"Tap","payload":{"state":"CLOSED"}}`,                   // a valve expose
	} {
		if _, err := invoke(m, "set_device", in, false); err == nil || !strings.Contains(err.Error(), "set_critical") {
			t.Errorf("set_device accepted %s: %v", in, err)
		}
	}
	if w := f.sent(); len(w) != 0 {
		t.Fatalf("refused input reached Zigbee2MQTT: %q", w)
	}
	// A plain plug (whose name merely contains "door") still switches with write.
	if _, err := invoke(m, "set_device", `{"device":"Outdoor plug","payload":{"state":"ON"}}`, false); err != nil {
		t.Fatal(err)
	}
	// set_critical still does the rest.
	if _, err := invoke(m, "set_critical", `{"device":"Garage","payload":{"trigger":true}}`, true); err != nil {
		t.Fatal(err)
	}
	r, err := invoke(m, "devices", `{}`, false)
	if err != nil {
		t.Fatal(err)
	}
	var ds []struct {
		Name     string `json:"name"`
		Critical bool   `json:"critical"`
	}
	if err := json.Unmarshal(r.Output, &ds); err != nil {
		t.Fatal(err)
	}
	crit := map[string]bool{}
	for _, d := range ds {
		crit[d.Name] = d.Critical
	}
	for _, n := range []string{"Front door", "Garage", "Smoke", "Main", "Keypad", "Gate relay", "Strip", "Tap"} {
		if !crit[n] {
			t.Errorf("%s isn't listed as critical: %s", n, r.Output)
		}
	}
	if crit["Outdoor plug"] {
		t.Error("the outdoor plug is critical")
	}
}

func TestZ2MCritName(t *testing.T) {
	for _, n := range []string{"pin_code", "user_code", "auto_relock", "unlock", "trigger", "garage_door", "gate", "door_state", "valve", "valve_state_l2",
		"silence", "mute", "self_test", "arm_mode", "alarm", "siren", "child_lock", "warning", "system_mode", "lock_state", "alarm_1"} {
		if !critName.MatchString(n) {
			t.Errorf("%s isn't critical", n)
		}
	}
	for _, n := range []string{"state", "brightness", "color_temp", "effect", "power_on_behavior", "indicator_mode", "clock", "led"} {
		if critName.MatchString(n) {
			t.Errorf("%s is critical", n)
		}
	}
}

// bridge/devices can be several MiB on a large network: it's read with its
// own larger limit (the general 1 MiB guard stays for everything else).
func TestZ2MLargeDeviceList(t *testing.T) {
	m, f := setup(t, nil)
	big := strings.Replace(devices, `"definition":null}`, `"definition":null,"pad":"`+strings.Repeat("x", 3<<20)+`"}`, 1)
	f.srv.Publish("zigbee2mqtt/bridge/devices", []byte(big), true, 0)
	if _, err := invoke(m, "devices", `{}`, false); err != nil {
		t.Fatal(err)
	}
	// Bridge info over 1 MiB is still refused.
	f.srv.Publish("zigbee2mqtt/bridge/info", []byte(`{"version":"2.1.0","pad":"`+strings.Repeat("x", 2<<20)+`"}`), true, 0)
	if _, err := invoke(m, "bridge", `{}`, false); err == nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Fatal(err)
	}
}
