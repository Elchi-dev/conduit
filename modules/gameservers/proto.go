package gameservers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"time"
)

// --- Minecraft Server List Ping (Java edition) -----------------------------

func putVarint(b *bytes.Buffer, v int32) {
	u := uint32(v)
	for {
		if u&^0x7F == 0 {
			b.WriteByte(byte(u))
			return
		}
		b.WriteByte(byte(u&0x7F | 0x80))
		u >>= 7
	}
}

func readVarint(r io.ByteReader) (int32, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v |= uint32(c&0x7F) << (7 * i)
		if c&0x80 == 0 {
			return int32(v), nil
		}
	}
	return 0, errors.New("varint too long")
}

func putString(b *bytes.Buffer, s string) {
	putVarint(b, int32(len(s)))
	b.WriteString(s)
}

// packet frames id+payload with its varint length.
func packet(id int32, payload []byte) []byte {
	var body bytes.Buffer
	putVarint(&body, id)
	body.Write(payload)
	var out bytes.Buffer
	putVarint(&out, int32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// mcStatus is the JSON a Minecraft server answers to a status request.
type mcStatus struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
		Sample []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"sample"`
	} `json:"players"`
	Description json.RawMessage `json:"description"`
}

// motd flattens the description, which is a string or a chat component.
func (s mcStatus) motd() string {
	var str string
	if json.Unmarshal(s.Description, &str) == nil {
		return str
	}
	var comp struct {
		Text  string `json:"text"`
		Extra []struct {
			Text string `json:"text"`
		} `json:"extra"`
	}
	if json.Unmarshal(s.Description, &comp) == nil {
		out := comp.Text
		for _, e := range comp.Extra {
			out += e.Text
		}
		return out
	}
	return ""
}

func minecraftPing(ctx context.Context, host string, port int) (mcStatus, time.Duration, error) {
	var st mcStatus
	d := net.Dialer{Timeout: 5 * time.Second}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return st, 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	var hs bytes.Buffer
	putVarint(&hs, -1) // protocol version: any
	putString(&hs, host)
	_ = binary.Write(&hs, binary.BigEndian, uint16(port))
	putVarint(&hs, 1) // next state: status
	if _, err := c.Write(append(packet(0, hs.Bytes()), packet(0, nil)...)); err != nil {
		return st, 0, err
	}
	r := bufio.NewReader(c)
	n, err := readVarint(r)
	if err != nil {
		return st, 0, fmt.Errorf("no answer: %w", err)
	}
	if n <= 0 || n > 1<<21 {
		return st, 0, errors.New("bad packet length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return st, 0, err
	}
	br := bytes.NewReader(body)
	if id, err := readVarint(br); err != nil || id != 0 {
		return st, 0, errors.New("unexpected packet")
	}
	l, err := readVarint(br)
	if err != nil || l < 0 || int(l) > br.Len() {
		return st, 0, errors.New("bad status string")
	}
	js := make([]byte, l)
	_, _ = io.ReadFull(br, js)
	if err := json.Unmarshal(js, &st); err != nil {
		return st, 0, fmt.Errorf("bad status JSON: %w", err)
	}
	return st, time.Since(start), nil
}

// --- Source RCON (also used by Minecraft) -------------------------------------

const (
	rconAuth         = 3
	rconAuthResponse = 2
	rconExec         = 2
	rconResponse     = 0
)

func writeRCON(w io.Writer, id, typ int32, body string) error {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, int32(4+4+len(body)+2))
	_ = binary.Write(&b, binary.LittleEndian, id)
	_ = binary.Write(&b, binary.LittleEndian, typ)
	b.WriteString(body)
	b.Write([]byte{0, 0})
	_, err := w.Write(b.Bytes())
	return err
}

func readRCON(r io.Reader) (id, typ int32, body string, err error) {
	var size int32
	if err = binary.Read(r, binary.LittleEndian, &size); err != nil {
		return
	}
	if size < 10 || size > 1<<16 {
		err = errors.New("bad RCON packet size")
		return
	}
	buf := make([]byte, size)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	id = int32(binary.LittleEndian.Uint32(buf[0:4]))
	typ = int32(binary.LittleEndian.Uint32(buf[4:8]))
	body = string(bytes.TrimRight(buf[8:], "\x00"))
	return
}

// rcon authenticates and runs one command, returning the server's answer.
func rcon(ctx context.Context, host string, port int, password, command string) (string, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	if err := writeRCON(c, 1, rconAuth, password); err != nil {
		return "", err
	}
	// Source servers send an empty response before the auth answer.
	for i := 0; i < 3; i++ {
		id, typ, _, err := readRCON(r)
		if err != nil {
			return "", fmt.Errorf("RCON: %w", err)
		}
		if typ != rconAuthResponse {
			continue
		}
		if id == -1 {
			return "", errors.New("the RCON password was refused")
		}
		if err := writeRCON(c, 2, rconExec, command); err != nil {
			return "", err
		}
		_, _, out, err := readRCON(r)
		return out, err
	}
	return "", errors.New("RCON: no authentication answer")
}

// --- Valve A2S queries over UDP ------------------------------------------------

type a2sInfo struct {
	Name       string `json:"name"`
	Map        string `json:"map"`
	Game       string `json:"game"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"maxPlayers"`
	Bots       int    `json:"bots"`
	Version    string `json:"version"`
	Password   bool   `json:"password"`
	VAC        bool   `json:"vac"`
}

type a2sPlayer struct {
	Name     string  `json:"name"`
	Score    int32   `json:"score"`
	Duration float32 `json:"secondsConnected"`
}

var header = []byte{0xFF, 0xFF, 0xFF, 0xFF}

// a2s sends a query, answering one challenge if the server asks for it.
func a2s(ctx context.Context, host string, port int, req []byte, withChallenge func(ch []byte) []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	buf := make([]byte, 1400)
	for attempt := 0; attempt < 3; attempt++ {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		n, err := c.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("no answer from %s:%d (UDP): %w", host, port, err)
		}
		p := buf[:n]
		if len(p) < 5 || !bytes.Equal(p[:4], header) {
			return nil, errors.New("not an A2S answer (split packets aren't supported)")
		}
		if p[4] == 0x41 && len(p) >= 9 { // challenge
			req = withChallenge(p[5:9])
			continue
		}
		return append([]byte(nil), p[4:]...), nil
	}
	return nil, errors.New("the server kept asking for a challenge")
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) byte() byte {
	if r.err != nil || len(r.b) < 1 {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) str() string {
	i := bytes.IndexByte(r.b, 0)
	if r.err != nil || i < 0 {
		r.err = io.ErrUnexpectedEOF
		return ""
	}
	s := string(r.b[:i])
	r.b = r.b[i+1:]
	return s
}

func (r *reader) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) skip(n int) {
	if r.err != nil || len(r.b) < n {
		r.err = io.ErrUnexpectedEOF
		return
	}
	r.b = r.b[n:]
}

func sourceInfo(ctx context.Context, host string, port int) (a2sInfo, time.Duration, error) {
	base := append(append([]byte(nil), header...), append([]byte("TSource Engine Query"), 0)...)
	start := time.Now()
	p, err := a2s(ctx, host, port, base, func(ch []byte) []byte { return append(append([]byte(nil), base...), ch...) })
	var in a2sInfo
	if err != nil {
		return in, 0, err
	}
	if p[0] != 0x49 {
		return in, 0, fmt.Errorf("unexpected A2S answer 0x%02x", p[0])
	}
	r := &reader{b: p[1:]}
	r.byte() // protocol
	in.Name, in.Map = r.str(), r.str()
	r.str() // folder
	in.Game = r.str()
	r.skip(2) // app id
	in.Players, in.MaxPlayers, in.Bots = int(r.byte()), int(r.byte()), int(r.byte())
	r.byte() // server type
	r.byte() // environment
	in.Password = r.byte() == 1
	in.VAC = r.byte() == 1
	in.Version = r.str()
	if r.err != nil {
		return in, 0, errors.New("short A2S_INFO answer")
	}
	return in, time.Since(start), nil
}

func sourcePlayers(ctx context.Context, host string, port int) ([]a2sPlayer, error) {
	mk := func(ch []byte) []byte { return append(append(append([]byte(nil), header...), 'U'), ch...) }
	p, err := a2s(ctx, host, port, mk([]byte{0xFF, 0xFF, 0xFF, 0xFF}), mk)
	if err != nil {
		return nil, err
	}
	if p[0] != 0x44 {
		return nil, fmt.Errorf("unexpected A2S answer 0x%02x", p[0])
	}
	r := &reader{b: p[1:]}
	n := int(r.byte())
	out := []a2sPlayer{}
	for i := 0; i < n && r.err == nil; i++ {
		r.byte() // index
		pl := a2sPlayer{Name: r.str(), Score: int32(r.u32())}
		pl.Duration = math.Float32frombits(r.u32())
		if r.err == nil {
			out = append(out, pl)
		}
	}
	return out, nil
}
