package ai

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ServeStdio bridges an MCP client that launches a command (stdio transport)
// to a running daemon's /mcp endpoint. Each line on in is one JSON-RPC
// message; each response is written to out as one line.
func ServeStdio(ctx context.Context, daemonURL, apiKey string, in io.Reader, out io.Writer, logw io.Writer) error {
	if apiKey == "" {
		return fmt.Errorf("set CONDUIT_API_KEY to an agent key (Conduit → API keys → Create key → An AI agent)")
	}
	endpoint := strings.TrimRight(daemonURL, "/") + "/mcp"
	client := &http.Client{Timeout: 10 * time.Minute}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(line))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		res, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(logw, "conduit mcp: daemon unreachable at %s: %v\n", endpoint, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		res.Body.Close()
		if res.StatusCode == http.StatusAccepted {
			continue
		}
		if res.StatusCode != http.StatusOK {
			fmt.Fprintf(logw, "conduit mcp: %s: %s\n", res.Status, strings.TrimSpace(string(body)))
			continue
		}
		if _, err := out.Write(append(bytes.TrimSpace(body), '\n')); err != nil {
			return err
		}
	}
	return sc.Err()
}
