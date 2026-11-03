// Package vault exposes the encrypted secret store as a module, so people,
// agents and automations use secrets through the same policy and audit trail
// as everything else.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cv "github.com/elchi-dev/conduit/internal/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// InstanceID is the fixed id of the vault's single instance.
const InstanceID = "vault"

// Module is the vault module.
type Module struct{ V *cv.Vault }

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "vault", Name: "Vault", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "Encrypted passwords, tokens, keys and one-time codes. Other modules use them by reference.",
		Presets:     []string{"developer", "gamer", "homelab", "team"},
		Actions: []sdk.ActionSpec{
			{Name: "list", Title: "Secrets", Description: "Names and details of every secret. Values stay hidden.", Risk: sdk.RiskRead},
			{Name: "reveal", Title: "Reveal a secret", Description: "Show a secret's value.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string","description":"Secret name, e.g. mail/work"}}}`)},
			{Name: "set", Title: "Save a secret", Description: "Create or replace a secret. Leave the value empty to generate a strong password.", Risk: sdk.RiskWrite, Sensitive: true,
				Input: schema(`{"type":"object","required":["name"],"properties":{
					"name":{"type":"string","description":"Lowercase letters, digits and . _ / -"},
					"value":{"type":"string","format":"password","description":"Leave empty to generate one"},
					"kind":{"type":"string","enum":["password","token","note","totp","ssh-key"],"default":"password"},
					"description":{"type":"string"},
					"length":{"type":"integer","minimum":16,"maximum":128,"default":24,"description":"Length of a generated password"}}}`)},
			{Name: "delete", Title: "Delete a secret", Description: "Remove a secret. Anything that references it stops working.", Risk: sdk.RiskDestructive,
				Input: schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)},
			{Name: "totp", Title: "One-time code", Description: "The current code for a stored two-factor (TOTP) secret.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)},
			{Name: "generate", Title: "Generate a password", Description: "A random password, not stored.", Risk: sdk.RiskRead, Sensitive: true,
				Input: schema(`{"type":"object","properties":{"length":{"type":"integer","minimum":16,"maximum":128,"default":24},"symbols":{"type":"boolean","default":true}}}`)},
			{Name: "import_csv", Title: "Import from a password manager", Description: "A CSV export from Bitwarden, 1Password, KeePass, LastPass, Proton Pass or a browser. Logins become passwords (usernames and addresses go in the description), two-factor secrets become one-time code secrets, secure notes become notes. Delete the export file afterwards.", Risk: sdk.RiskWrite, Sensitive: true,
				Input: schema(`{"type":"object","required":["text"],"properties":{"text":{"type":"string","x-multiline":true,"description":"Paste the CSV file's contents"},"prefix":{"type":"string","description":"Folder for the imported secrets, e.g. bitwarden","default":"imported"},"overwrite":{"type":"boolean","default":false,"description":"Replace secrets that already exist under the same name"}}}`)},
			{Name: "import_env", Title: "Import a .env file", Description: "Store every KEY=value line as a secret under a prefix.", Risk: sdk.RiskWrite, Sensitive: true,
				Input: schema(`{"type":"object","required":["text"],"properties":{"text":{"type":"string","x-multiline":true,"description":"Paste the file's contents"},"prefix":{"type":"string","description":"e.g. myapp"}}}`)},
			{Name: "rotate", Title: "Rotate a secret", Description: "Get a fresh value from the service that issued it and store it; the old value stops working.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["name","provider"],"properties":{"name":{"type":"string"},"provider":{"type":"string","enum":["cloudflare"],"description":"Who issued it"}}}`)},
			{Name: "scan_text", Title: "Check text for leaks", Description: "Find any vault secret pasted in this text, e.g. a log or a config file.", Risk: sdk.RiskRead, Sensitive: true,
				Input: schema(`{"type":"object","required":["text"],"properties":{"text":{"type":"string","x-multiline":true}}}`)},
			{Name: "scan_path", Title: "Check a folder for leaks", Description: "Search files on this machine (e.g. a code repository) for vault secret values.", Risk: sdk.RiskRead,
				Input: schema(`{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"Folder or file on the machine running Conduit"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "secret", Title: "Secrets", ListAction: "list", ViewHint: "table"}},
		Events: []sdk.EventSpec{
			{Type: "vault.leak", Description: "A secret's value was found where it should not be"},
		},
	}
}

// Configure implements sdk.Module; the vault has no settings.
func (m *Module) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, _ string) sdk.Health {
	st, err := m.V.Status(ctx)
	switch {
	case err != nil:
		return sdk.Health{Status: "down", Message: err.Error()}
	case !st.SetUp:
		return sdk.Health{Status: "unconfigured", Message: "Set a vault passphrase to start storing secrets"}
	case !st.Unlocked:
		return sdk.Health{Status: "degraded", Message: "Locked. Unlock it so modules can use their secrets"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("Unlocked, %d secrets", st.Secrets)}
}

// Close implements sdk.Module.
func (m *Module) Close(string) error { return nil }

type nameIn struct {
	Name string `json:"name"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	out := func(v any) (sdk.Result, error) {
		b, err := json.Marshal(v)
		return sdk.Result{Output: b}, err
	}
	switch c.Action {
	case "list":
		l, err := m.V.List(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return out(l)

	case "reveal":
		var in nameIn
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		v, err := m.V.Get(ctx, in.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		return out(map[string]string{"name": in.Name, "value": v})

	case "set":
		var in struct {
			Name        string  `json:"name"`
			Value       string  `json:"value"`
			Kind        cv.Kind `json:"kind"`
			Description string  `json:"description"`
			Length      int     `json:"length"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		generated := false
		if in.Value == "" {
			if in.Length == 0 {
				in.Length = 24
			}
			g, err := cv.Generate(in.Length, true)
			if err != nil {
				return sdk.Result{}, err
			}
			in.Value, generated = g, true
		}
		if in.Kind == cv.KindTOTP {
			if _, _, err := cv.TOTP(in.Value, time.Now()); err != nil {
				return sdk.Result{}, err
			}
		}
		if err := m.V.Put(ctx, cv.Meta{Name: in.Name, Kind: in.Kind, Description: in.Description}, in.Value); err != nil {
			return sdk.Result{}, err
		}
		res := map[string]any{"name": in.Name, "reference": "secret://" + in.Name, "generated": generated}
		if generated {
			res["value"] = in.Value
		}
		return out(res)

	case "delete":
		var in nameIn
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		if err := m.V.Delete(ctx, in.Name); err != nil {
			return sdk.Result{}, err
		}
		return out(map[string]string{"deleted": in.Name})

	case "rotate":
		var in struct {
			Name     string `json:"name"`
			Provider string `json:"provider"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		if err := m.V.Rotate(ctx, in.Name, in.Provider); err != nil {
			return sdk.Result{}, err
		}
		return out(map[string]string{"rotated": in.Name})

	case "totp":
		var in nameIn
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		v, err := m.V.Get(ctx, in.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		code, left, err := cv.TOTP(v, time.Now())
		if err != nil {
			return sdk.Result{}, err
		}
		return out(map[string]any{"name": in.Name, "code": code, "secondsLeft": left})

	case "generate":
		var in struct {
			Length  int   `json:"length"`
			Symbols *bool `json:"symbols"`
		}
		_ = json.Unmarshal(c.Input, &in)
		if in.Length == 0 {
			in.Length = 24
		}
		sym := in.Symbols == nil || *in.Symbols
		p, err := cv.Generate(in.Length, sym)
		if err != nil {
			return sdk.Result{}, err
		}
		return out(map[string]string{"password": p})

	case "import_env":
		var in struct {
			Text   string `json:"text"`
			Prefix string `json:"prefix"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		env, err := cv.ParseEnv(strings.NewReader(in.Text))
		if err != nil {
			return sdk.Result{}, err
		}
		var names []string
		for k, v := range env {
			n := cv.EnvName(in.Prefix, k)
			if err := m.V.Put(ctx, cv.Meta{Name: n, Kind: cv.KindToken, Description: "Imported from " + k}, v); err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", k, err)
			}
			names = append(names, n)
		}
		return out(map[string]any{"imported": len(names), "names": names})

	case "import_csv":
		var in struct {
			Text      string `json:"text"`
			Prefix    string `json:"prefix"`
			Overwrite bool   `json:"overwrite"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		items, err := cv.ParseCSVExport(strings.NewReader(in.Text), in.Prefix)
		if err != nil {
			return sdk.Result{}, err
		}
		existing := map[string]bool{}
		if !in.Overwrite {
			list, err := m.V.List(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, x := range list {
				existing[x.Name] = true
			}
		}
		names, skipped := []string{}, []string{}
		for _, it := range items {
			if existing[it.Name] {
				skipped = append(skipped, it.Name)
				continue
			}
			if err := m.V.Put(ctx, cv.Meta{Name: it.Name, Kind: it.Kind, Description: it.Description(), Tags: []string{"imported"}}, it.Value); err != nil {
				return sdk.Result{}, fmt.Errorf("%s: %w", it.Name, err)
			}
			names = append(names, it.Name)
		}
		return out(map[string]any{"imported": len(names), "names": names, "skipped": skipped})

	case "scan_text":
		var in struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		leaks, err := m.V.ScanText(ctx, in.Text)
		if err != nil {
			return sdk.Result{}, err
		}
		return out(nonNil(leaks))

	case "scan_path":
		var in struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return sdk.Result{}, err
		}
		if in.Path == "" {
			return sdk.Result{}, errors.New("path is required")
		}
		leaks, scanned, err := m.V.ScanPath(ctx, in.Path, 0)
		if err != nil {
			return sdk.Result{}, err
		}
		return out(map[string]any{"filesScanned": scanned, "leaks": nonNil(leaks)})
	}
	return sdk.Result{}, fmt.Errorf("unknown action %q", c.Action)
}

func nonNil(l []cv.Leak) []cv.Leak {
	if l == nil {
		return []cv.Leak{}
	}
	return l
}
