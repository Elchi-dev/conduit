// Package mdns announces a Conduit daemon on the local network with
// multicast DNS service discovery (RFC 6762, RFC 6763) and finds the others.
// It implements only what that needs: PTR, SRV, TXT, A and AAAA records,
// reading compressed names, writing uncompressed ones.
package mdns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// Record types.
const (
	TypeA    uint16 = 1
	TypePTR  uint16 = 12
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeSRV  uint16 = 33
	TypeANY  uint16 = 255
)

const classIN = 1

// cacheFlush marks records this responder owns exclusively (RFC 6762 §10.2).
const cacheFlush = 0x8000

// unicastResponse in a question's class asks for a unicast answer.
const unicastResponse = 0x8000

// Question is one entry of the question section.
type Question struct {
	Name string
	Type uint16
	// Unicast is the QU bit: the asker wants the answer sent straight back.
	Unicast bool
}

// RR is a resource record. Only the fields for its Type are used.
type RR struct {
	Name   string
	Type   uint16
	TTL    uint32
	Flush  bool
	Target string   // PTR, SRV
	Port   uint16   // SRV
	TXT    []string // TXT
	IP     net.IP   // A, AAAA
}

// Message is a DNS message.
type Message struct {
	ID        uint16
	Response  bool
	Questions []Question
	Answers   []RR // answers and additional records together when parsed
}

var errShort = errors.New("mdns: message too short")

// canonical lowercases a name and makes sure it ends with a dot.
func canonical(n string) string {
	n = strings.ToLower(n)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

func appendName(b []byte, name string) []byte {
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// Pack encodes a message. Answers go into the answer section.
func (m Message) Pack() []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], m.ID)
	if m.Response {
		binary.BigEndian.PutUint16(b[2:], 0x8400) // response, authoritative
	}
	binary.BigEndian.PutUint16(b[4:], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(b[6:], uint16(len(m.Answers)))
	for _, q := range m.Questions {
		b = appendName(b, q.Name)
		cls := uint16(classIN)
		if q.Unicast {
			cls |= unicastResponse
		}
		b = binary.BigEndian.AppendUint16(b, q.Type)
		b = binary.BigEndian.AppendUint16(b, cls)
	}
	for _, r := range m.Answers {
		b = appendName(b, r.Name)
		b = binary.BigEndian.AppendUint16(b, r.Type)
		cls := uint16(classIN)
		if r.Flush {
			cls |= cacheFlush
		}
		b = binary.BigEndian.AppendUint16(b, cls)
		b = binary.BigEndian.AppendUint32(b, r.TTL)
		var rd []byte
		switch r.Type {
		case TypePTR:
			rd = appendName(nil, r.Target)
		case TypeSRV:
			rd = binary.BigEndian.AppendUint16(rd, 0) // priority
			rd = binary.BigEndian.AppendUint16(rd, 0) // weight
			rd = binary.BigEndian.AppendUint16(rd, r.Port)
			rd = appendName(rd, r.Target)
		case TypeTXT:
			for _, t := range r.TXT {
				if len(t) > 255 {
					t = t[:255]
				}
				rd = append(rd, byte(len(t)))
				rd = append(rd, t...)
			}
			if len(rd) == 0 {
				rd = []byte{0}
			}
		case TypeA:
			rd = append(rd, r.IP.To4()...)
		case TypeAAAA:
			rd = append(rd, r.IP.To16()...)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
		b = append(b, rd...)
	}
	return b
}

// readName reads a possibly compressed name at off and returns it with the
// offset just after it in the original position.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, ".") + ".", end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errShort
			}
			if end < 0 {
				end = off + 2
			}
			jumps++
			if jumps > 16 {
				return "", 0, errors.New("mdns: name compression loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errors.New("mdns: bad label")
		default:
			if off+1+l > len(msg) {
				return "", 0, errShort
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
			if len(labels) > 128 {
				return "", 0, errors.New("mdns: name too long")
			}
		}
	}
}

// Unpack decodes a message. Answer, authority and additional records all
// end up in Answers.
func Unpack(msg []byte) (Message, error) {
	var m Message
	if len(msg) < 12 {
		return m, errShort
	}
	m.ID = binary.BigEndian.Uint16(msg)
	m.Response = msg[2]&0x80 != 0
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	rr := int(binary.BigEndian.Uint16(msg[6:])) + int(binary.BigEndian.Uint16(msg[8:])) + int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off)
		if err != nil || n+4 > len(msg) {
			return m, errShort
		}
		cls := binary.BigEndian.Uint16(msg[n+2:])
		m.Questions = append(m.Questions, Question{Name: canonical(name), Type: binary.BigEndian.Uint16(msg[n:]), Unicast: cls&unicastResponse != 0})
		off = n + 4
	}
	for i := 0; i < rr; i++ {
		name, n, err := readName(msg, off)
		if err != nil || n+10 > len(msg) {
			return m, errShort
		}
		r := RR{Name: canonical(name), Type: binary.BigEndian.Uint16(msg[n:])}
		cls := binary.BigEndian.Uint16(msg[n+2:])
		r.Flush = cls&cacheFlush != 0
		r.TTL = binary.BigEndian.Uint32(msg[n+4:])
		rdl := int(binary.BigEndian.Uint16(msg[n+8:]))
		start := n + 10
		if start+rdl > len(msg) {
			return m, errShort
		}
		rd := msg[start : start+rdl]
		switch r.Type {
		case TypePTR:
			if t, _, err := readName(msg, start); err == nil {
				r.Target = canonical(t)
			}
		case TypeSRV:
			if rdl >= 7 {
				r.Port = binary.BigEndian.Uint16(rd[4:])
				if t, _, err := readName(msg, start+6); err == nil {
					r.Target = canonical(t)
				}
			}
		case TypeTXT:
			for p := 0; p < len(rd); {
				l := int(rd[p])
				if p+1+l > len(rd) {
					break
				}
				if l > 0 {
					r.TXT = append(r.TXT, string(rd[p+1:p+1+l]))
				}
				p += 1 + l
			}
		case TypeA:
			if rdl == 4 {
				r.IP = net.IP(append([]byte{}, rd...))
			}
		case TypeAAAA:
			if rdl == 16 {
				r.IP = net.IP(append([]byte{}, rd...))
			}
		}
		m.Answers = append(m.Answers, r)
		off = start + rdl
	}
	return m, nil
}
