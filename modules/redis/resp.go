package redis

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// A minimal RESP2 client: enough for the commands this module sends.

type client struct {
	c  net.Conn
	rd *bufio.Reader
}

func dial(addr string, useTLS bool, timeout time.Duration) (*client, error) {
	d := &net.Dialer{Timeout: timeout}
	var c net.Conn
	var err error
	if useTLS {
		host, _, _ := net.SplitHostPort(addr)
		c, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
	} else {
		c, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	return &client{c: c, rd: bufio.NewReader(c)}, nil
}

func (c *client) Close() error { return c.c.Close() }

// Error is a Redis error reply.
type Error string

func (e Error) Error() string { return string(e) }

// do sends a command and reads one reply: string, int64, nil, []any or Error.
func (c *client) do(args ...string) (any, error) {
	buf := []byte("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		buf = append(buf, '$')
		buf = strconv.AppendInt(buf, int64(len(a)), 10)
		buf = append(buf, "\r\n"...)
		buf = append(buf, a...)
		buf = append(buf, "\r\n"...)
	}
	if _, err := c.c.Write(buf); err != nil {
		return nil, err
	}
	v, err := readReply(c.rd, 0)
	if err != nil {
		return nil, err
	}
	if e, ok := v.(Error); ok {
		return nil, e
	}
	return v, nil
}

const maxBulk = 4 << 20

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("redis: malformed reply")
	}
	return line[:len(line)-2], nil
}

func readReply(r *bufio.Reader, depth int) (any, error) {
	if depth > 8 {
		return nil, errors.New("redis: reply nested too deep")
	}
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, errors.New("redis: empty reply")
	}
	body := line[1:]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return Error(body), nil
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		if n > maxBulk {
			// Skip what we won't keep, keep the start.
			head := make([]byte, 4096)
			if _, err := io.ReadFull(r, head); err != nil {
				return nil, err
			}
			if _, err := r.Discard(n - 4096 + 2); err != nil {
				return nil, err
			}
			return string(head), nil
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return string(b[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		if n > 100000 {
			return nil, errors.New("redis: reply too large")
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = readReply(r, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unexpected reply type %q", line[0])
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return ""
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}
