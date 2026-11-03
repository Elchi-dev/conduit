package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HubTransport stores each collection as an encrypted blob on the hub the
// daemon is linked to. Daemons in a group must be linked to the same hub
// account to meet there.
type HubTransport struct {
	Base  string // hub URL
	Token string // the daemon's device token
	HTTP  *http.Client
}

func (h *HubTransport) Name() string { return "hub" }

func (h *HubTransport) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.Base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	c := h.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	return res.StatusCode, nil
}

type hubBlob struct {
	Version int64  `json:"version"`
	Data    string `json:"data"`
}

// Exchange merges with the hub's copy and writes the result back, retrying
// when another daemon wrote in between.
func (h *HubTransport) Exchange(ctx context.Context, key []byte, mine Doc, merge func(Doc) Doc) (Doc, error) {
	path := "/v1/sync/" + url.PathEscape("sync-"+GroupID(key)+"-"+mine.Collection)
	var cur hubBlob
	code, err := h.do(ctx, http.MethodGet, path, nil, &cur)
	if err != nil {
		return Doc{}, err
	}
	if code == http.StatusNotFound {
		cur = hubBlob{}
	} else if code != http.StatusOK {
		return Doc{}, fmt.Errorf("the hub answered %d", code)
	}
	for attempt := 0; attempt < 4; attempt++ {
		merged := mine
		if cur.Data != "" {
			theirs, err := Open(key, mine.Collection, cur.Data)
			if err != nil {
				return Doc{}, err
			}
			merged = merge(theirs)
		}
		sealed, err := Seal(key, merged)
		if err != nil {
			return Doc{}, err
		}
		var conflict struct {
			Current hubBlob `json:"current"`
		}
		code, err := h.do(ctx, http.MethodPut, path, hubBlob{Version: cur.Version, Data: sealed}, &conflict)
		if err != nil {
			return Doc{}, err
		}
		switch code {
		case http.StatusOK:
			return merged, nil
		case http.StatusConflict:
			if conflict.Current.Version == 0 {
				// It was deleted, or never existed: read it again.
				if c, err := h.do(ctx, http.MethodGet, path, nil, &cur); err != nil || (c != http.StatusOK && c != http.StatusNotFound) {
					return Doc{}, fmt.Errorf("the hub answered %d", c)
				}
				continue
			}
			cur = conflict.Current
			continue
		case http.StatusRequestEntityTooLarge:
			return Doc{}, errors.New("this collection is larger than the hub's 1 MiB limit for one blob; sync it with a peer instead")
		default:
			return Doc{}, fmt.Errorf("the hub answered %d", code)
		}
	}
	return Doc{}, errors.New("other daemons kept writing at the same time; will try again next round")
}

// PeerTransport syncs directly with another daemon in the group.
type PeerTransport struct {
	Base string
	HTTP *http.Client
}

func (p *PeerTransport) Name() string { return "peer " + p.Base }

// Exchange sends our document; the peer merges, applies and returns the
// merged document.
func (p *PeerTransport) Exchange(ctx context.Context, key []byte, mine Doc, merge func(Doc) Doc) (Doc, error) {
	sealed, err := Seal(key, mine)
	if err != nil {
		return Doc{}, err
	}
	b, _ := json.Marshal(map[string]string{"collection": mine.Collection, "doc": sealed})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Base+"/sync/exchange", bytes.NewReader(b))
	if err != nil {
		return Doc{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := p.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return Doc{}, fmt.Errorf("couldn't reach %s: %w", p.Base, err)
	}
	defer res.Body.Close()
	var out struct {
		Doc   string `json:"doc"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&out)
	if res.StatusCode != http.StatusOK {
		if out.Error == "" {
			out.Error = res.Status
		}
		return Doc{}, fmt.Errorf("%s: %s", p.Base, out.Error)
	}
	theirs, err := Open(key, mine.Collection, out.Doc)
	if err != nil {
		return Doc{}, err
	}
	return merge(theirs), nil
}
