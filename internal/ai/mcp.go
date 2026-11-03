package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/elchi-dev/conduit/internal/version"
)

// MCP protocol versions this server speaks, newest first.
var mcpVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

const instructions = `Conduit manages the user's computers, servers, containers, mail, calendars, secrets and more.
Call conduit_overview first to see what's connected. Tools named <system>__<action> act on one system.
Read-only tools run immediately. Changes may need the owner's approval: you'll get an approval id; tell the user
what you asked for and check back with conduit_approval_status. Use conduit_preview before risky changes when a tool
supports it. Never try to get around a denial. Everything you do is recorded in the owner's timeline.`

// HandleMCP answers one MCP request or batch (streamable HTTP transport,
// JSON responses). Notifications get 202 with no body.
func HandleMCP(w http.ResponseWriter, r *http.Request, tb *Toolbox) {
	if r.Method == http.MethodGet {
		// No server-initiated stream: tool calls answer synchronously.
		w.Header().Set("Allow", "POST")
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusOK) // sessions are stateless; nothing to end
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	trimmed := strings.TrimSpace(string(body))
	var reqs []rpcReq
	batch := strings.HasPrefix(trimmed, "[")
	if batch {
		err = json.Unmarshal(body, &reqs)
	} else {
		var one rpcReq
		err = json.Unmarshal(body, &one)
		reqs = []rpcReq{one}
	}
	if err != nil {
		writeRPC(w, rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{-32700, "parse error"}})
		return
	}
	var out []rpcResp
	for _, q := range reqs {
		res, e := Dispatch(r.Context(), tb, q.Method, q.Params)
		if len(q.ID) == 0 {
			continue // notification
		}
		resp := rpcResp{JSONRPC: "2.0", ID: q.ID}
		if e != nil {
			resp.Error = e
		} else {
			resp.Result = res
		}
		out = append(out, resp)
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if batch {
		writeRPC(w, out)
		return
	}
	writeRPC(w, out[0])
}

func writeRPC(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Dispatch handles one MCP method.
func Dispatch(ctx context.Context, tb *Toolbox, method string, params json.RawMessage) (any, *rpcErr) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		v := mcpVersions[0]
		for _, s := range mcpVersions {
			if s == p.ProtocolVersion {
				v = s
			}
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "conduit", "title": "Conduit", "version": version.Version},
			"instructions":    instructions,
		}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := tb.Tools()
		if tools == nil {
			tools = []Tool{}
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
			return nil, &rpcErr{-32602, "tools/call needs a name"}
		}
		res := tb.Call(ctx, p.Name, p.Arguments)
		out := map[string]any{
			"content": []map[string]string{{"type": "text", "text": res.Text}},
			"isError": res.IsError,
		}
		if res.Pending != nil {
			out["structuredContent"] = map[string]any{"approvalId": res.Pending.ID, "status": "pending"}
		}
		return out, nil
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	}
	return nil, &rpcErr{-32601, "method not found: " + method}
}
