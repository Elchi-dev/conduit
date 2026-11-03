package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// Rotation (signature feature 7, with leak scanning): replace a secret with a
// fresh value at the service that issued it, then store the new value. The
// old value stops working, so a leaked copy is useless.

// Rotator issues a new value for a secret given the current one.
type Rotator interface {
	ID() string
	Title() string
	Rotate(ctx context.Context, current string) (string, error)
}

var rotators = map[string]Rotator{}

// RegisterRotator adds a rotation provider.
func RegisterRotator(r Rotator) { rotators[r.ID()] = r }

// Rotators lists the available providers.
func Rotators() []map[string]string {
	out := []map[string]string{}
	for _, r := range rotators {
		out = append(out, map[string]string{"id": r.ID(), "title": r.Title()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"] < out[j]["id"] })
	return out
}

// Rotate replaces a secret through a provider and stores the new value,
// keeping its metadata.
func (v *Vault) Rotate(ctx context.Context, name, provider string) error {
	r, ok := rotators[provider]
	if !ok {
		return fmt.Errorf("no rotation provider %q", provider)
	}
	cur, err := v.Get(ctx, name)
	if err != nil {
		return err
	}
	var meta Meta
	list, err := v.List(ctx)
	if err != nil {
		return err
	}
	for _, m := range list {
		if m.Name == name {
			meta = m
		}
	}
	next, err := r.Rotate(ctx, cur)
	if err != nil {
		return fmt.Errorf("%s refused the rotation: %w", r.Title(), err)
	}
	if next == "" || next == cur {
		return errors.New("the provider returned no new value")
	}
	if err := v.Put(ctx, meta, next); err != nil {
		// The old value is already dead at the provider: surface the new
		// one's loss loudly rather than silently.
		return fmt.Errorf("rotated at %s but couldn't store the new value: %w", r.Title(), err)
	}
	return nil
}

// Cloudflare rolls a Cloudflare API token: the token itself must be allowed
// to roll (permission "API Tokens Write" on the user).
type Cloudflare struct {
	API  string // default https://api.cloudflare.com/client/v4
	HTTP *http.Client
}

func (Cloudflare) ID() string    { return "cloudflare" }
func (Cloudflare) Title() string { return "Cloudflare API token" }

func (c Cloudflare) Rotate(ctx context.Context, current string) (string, error) {
	api := c.API
	if api == "" {
		api = "https://api.cloudflare.com/client/v4"
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	call := func(method, path string, out any) error {
		var body *bytes.Reader
		if method == http.MethodPut {
			body = bytes.NewReader([]byte(`{}`))
		} else {
			body = bytes.NewReader(nil)
		}
		req, _ := http.NewRequestWithContext(ctx, method, api+path, body)
		req.Header.Set("Authorization", "Bearer "+current)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		var e struct {
			Success bool            `json:"success"`
			Result  json.RawMessage `json:"result"`
			Errors  []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			return err
		}
		if !e.Success {
			if len(e.Errors) > 0 {
				return errors.New(e.Errors[0].Message)
			}
			return errors.New(res.Status)
		}
		return json.Unmarshal(e.Result, out)
	}
	var tok struct {
		ID string `json:"id"`
	}
	if err := call(http.MethodGet, "/user/tokens/verify", &tok); err != nil {
		return "", err
	}
	var next string
	if err := call(http.MethodPut, "/user/tokens/"+tok.ID+"/value", &next); err != nil {
		return "", err
	}
	return next, nil
}

func init() { RegisterRotator(Cloudflare{}) }
