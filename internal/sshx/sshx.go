// Package sshx is the SSH client shared by the servers and Docker modules.
//
// Host keys are pinned: a connection is only made when the server presents
// the SHA-256 fingerprint stored in the instance's settings. On the first
// attempt without a pinned key, the error tells the person the fingerprint to
// check and pin, so nobody is silently trusted on first use.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is the SSH part of a module's settings.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`   // secret:// reference
	Key      string `json:"privateKey"` // secret:// reference to a PEM private key
	HostKey  string `json:"hostKey"`    // "SHA256:…" fingerprint
}

// SchemaProps is the JSON Schema properties block for Config, for embedding
// in a module's config schema.
const SchemaProps = `"host":{"type":"string","description":"Hostname or IP address"},
"port":{"type":"integer","default":22},
"user":{"type":"string","default":"root"},
"privateKey":{"type":"string","x-secret":true,"title":"Private key","description":"Vault reference to a private key (recommended)"},
"password":{"type":"string","x-secret":true,"description":"Vault reference to a password, if you don't use a key"},
"hostKey":{"type":"string","title":"Host key fingerprint","description":"SHA256:… Leave empty on first connect; Conduit will show the fingerprint to check and paste here."}`

// HostKeyError is returned when the server's key is not (yet) pinned.
type HostKeyError struct {
	Got      string
	Expected string
}

func (e *HostKeyError) Error() string {
	if e.Expected == "" {
		return fmt.Sprintf("this server's host key is %s. Check it matches the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), then paste it into Host key fingerprint in settings", e.Got)
	}
	return fmt.Sprintf("host key changed: expected %s, got %s. The server may have been reinstalled, or someone is intercepting the connection", e.Expected, e.Got)
}

// Client is a reconnecting SSH client for one module instance.
type Client struct {
	cfg  Config
	host sdk.Host

	mu   sync.Mutex
	conn *ssh.Client
}

// New returns a client; it connects lazily.
func New(cfg Config, h sdk.Host) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("host is required")
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Password == "" && cfg.Key == "" {
		return nil, errors.New("set a private key or a password (as vault references)")
	}
	return &Client{cfg: cfg, host: h}, nil
}

func (c *Client) dial(ctx context.Context) (*ssh.Client, error) {
	var auths []ssh.AuthMethod
	if c.cfg.Key != "" {
		pem, err := c.host.Secret(ctx, c.cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey([]byte(pem))
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if c.cfg.Password != "" {
		pw, err := c.host.Secret(ctx, c.cfg.Password)
		if err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
		auths = append(auths, ssh.Password(pw))
	}
	want := strings.TrimSpace(c.cfg.HostKey)
	conf := &ssh.ClientConfig{
		User: c.cfg.User,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if want == "" || got != want {
				return &HostKeyError{Got: got, Expected: want}
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	// Through the instance's network when it has one (sdk.NetHost).
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	nc, err := sdk.DialContext(c.host)(dctx, "tcp", addr)
	cancel()
	if err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, addr, conf)
	if err != nil {
		nc.Close()
		var hk *HostKeyError
		if errors.As(err, &hk) {
			return nil, hk
		}
		return nil, err
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// Conn returns a live connection, reconnecting if needed.
func (c *Client) Conn(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		if _, _, err := c.conn.SendRequest("keepalive@conduit", true, nil); err == nil {
			return c.conn, nil
		}
		c.conn.Close()
		c.conn = nil
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

// Result of a remote command.
type Result struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

// Run executes a command and collects its output (each stream capped at 4 MiB).
func (c *Client) Run(ctx context.Context, cmd string) (Result, error) {
	conn, err := c.Conn(ctx)
	if err != nil {
		return Result{}, err
	}
	sess, err := conn.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer sess.Close()
	var out, errb capped
	sess.Stdout, sess.Stderr = &out, &errb
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		return Result{}, ctx.Err()
	case err := <-done:
		r := Result{Stdout: out.String(), Stderr: errb.String()}
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			r.ExitCode = ee.ExitStatus()
			return r, nil
		}
		return r, err
	}
}

// DialUnix opens a stream to a Unix socket on the remote host (used for the
// Docker socket).
func (c *Client) DialUnix(ctx context.Context, path string) (net.Conn, error) {
	conn, err := c.Conn(ctx)
	if err != nil {
		return nil, err
	}
	return conn.Dial("unix", path)
}

// Close closes the connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

type capped struct {
	b []byte
}

const capBytes = 4 << 20

func (c *capped) Write(p []byte) (int, error) {
	if room := capBytes - len(c.b); room > 0 {
		if len(p) > room {
			c.b = append(c.b, p[:room]...)
		} else {
			c.b = append(c.b, p...)
		}
	}
	return len(p), nil
}

func (c *capped) String() string { return string(c.b) }

// Quote returns s as a single-quoted POSIX shell word.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
