package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type secrets map[string]string

func (s secrets) Secret(_ context.Context, ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", errors.New("no such secret")
}
func (secrets) Publish(context.Context, sdk.Event) {}
func (secrets) Log(string, string, ...any)         {}

// fakeServer runs commands by echoing them back, prefixed.
func fakeServer(t *testing.T) (addr string, fingerprint string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	conf := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "ops" && string(pw) == "pw" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	conf.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, conf)
				if err != nil {
					return
				}
				go func() {
					for r := range reqs {
						if r.WantReply {
							r.Reply(true, nil)
						}
					}
				}()
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						for r := range creqs {
							if r.Type == "exec" {
								cmd := string(r.Payload[4:])
								r.Reply(true, nil)
								ch.Write([]byte("ran: " + cmd))
								code := []byte{0, 0, 0, 0}
								if strings.Contains(cmd, "fail") {
									code[3] = 3
								}
								ch.SendRequest("exit-status", false, code)
								ch.Close()
								return
							}
							r.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func TestHostKeyPinning(t *testing.T) {
	addr, fp := fakeServer(t)
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	h := secrets{"secret://pw": "pw"}
	ctx := context.Background()

	c, _ := New(Config{Host: host, Port: p, User: "ops", Password: "secret://pw"}, h)
	_, err := c.Run(ctx, "uptime")
	var hk *HostKeyError
	if !errors.As(err, &hk) || hk.Got != fp || hk.Expected != "" {
		t.Fatalf("unpinned connect: %v", err)
	}
	if !strings.Contains(err.Error(), fp) {
		t.Fatal("error should show the fingerprint to pin")
	}

	c, _ = New(Config{Host: host, Port: p, User: "ops", Password: "secret://pw", HostKey: "SHA256:wrong"}, h)
	if _, err := c.Run(ctx, "uptime"); !errors.As(err, &hk) || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("wrong pin: %v", err)
	}

	c, _ = New(Config{Host: host, Port: p, User: "ops", Password: "secret://pw", HostKey: fp}, h)
	r, err := c.Run(ctx, "uptime")
	if err != nil || r.Stdout != "ran: uptime" || r.ExitCode != 0 {
		t.Fatalf("pinned run: %+v %v", r, err)
	}
	r, err = c.Run(ctx, "fail now")
	if err != nil || r.ExitCode != 3 {
		t.Fatalf("exit code: %+v %v", r, err)
	}
	c.Close()
}

func TestQuote(t *testing.T) {
	if got := Quote(`it's; rm -rf /`); got != `'it'\''s; rm -rf /'` {
		t.Fatalf("quote = %s", got)
	}
}
