package l7

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Frame size limits for the pre-play protocol states. Real clients never come
// close to these; oversized frames are treated as protocol violations.
const (
	maxHandshakeFrame = 2048
	maxLoginFrame     = 4096
	maxStatusFrame    = 128
	maxStatusResponse = 1 << 21 // 2 MiB status JSON from the backend
)

var (
	errLegacyPing     = errors.New("l7: legacy server list ping")
	errFrameTooLarge  = errors.New("l7: frame exceeds limit")
	errVarIntTooLong  = errors.New("l7: varint too long")
	errMalformedFrame = errors.New("l7: malformed frame")
)

const (
	stateStatus = 1
	stateLogin  = 2
	// Modern clients may use the transfer intent which behaves like login.
	stateTransfer = 3
)

func readVarInt(r io.ByteReader) (int32, int, error) {
	var value int32
	for i := 0; ; i++ {
		if i >= 5 {
			return 0, i, errVarIntTooLong
		}
		b, err := r.ReadByte()
		if err != nil {
			return 0, i, err
		}
		value |= int32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
	}
}

func appendVarInt(dst []byte, v int32) []byte {
	u := uint32(v)
	for {
		b := byte(u & 0x7f)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if u == 0 {
			return dst
		}
	}
}

// readFrame reads one length-prefixed packet from br. It returns the packet
// payload and the raw wire bytes (length prefix included) so that consumed
// frames can be replayed verbatim to the backend.
func readFrame(br *bufio.Reader, max int32) (payload []byte, raw []byte, err error) {
	// A legacy (pre-1.7) server list ping starts with 0xFE which cannot be a
	// valid frame in this position for modern clients.
	if head, err := br.Peek(1); err == nil && head[0] == 0xfe {
		return nil, nil, errLegacyPing
	}
	length, n, err := readVarInt(br)
	if err != nil {
		return nil, nil, err
	}
	if length <= 0 || length > max {
		return nil, nil, errFrameTooLarge
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, nil, err
	}
	raw = appendVarInt(make([]byte, 0, n+int(length)), length)
	raw = append(raw, payload...)
	return payload, raw, nil
}

type handshake struct {
	protocol  int32
	address   string
	port      uint16
	nextState int32
}

// clientType returns the client type detectable from the handshake address
// markers. Forge appends \0FML\0, \0FML2\0 or \0FORGE to the address; Fabric
// does not modify the handshake at all and is indistinguishable from vanilla.
func (h handshake) clientType() string {
	upper := strings.ToUpper(h.address)
	if strings.Contains(upper, "\x00FML") || strings.Contains(upper, "\x00FORGE") {
		return "forge"
	}
	return "vanilla"
}

func parseString(r *bytes.Reader, maxLen int32) (string, error) {
	l, _, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	if l < 0 || l > maxLen || int(l) > r.Len() {
		return "", errMalformedFrame
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func parseHandshake(payload []byte) (handshake, error) {
	var h handshake
	r := bytes.NewReader(payload)
	id, _, err := readVarInt(r)
	if err != nil || id != 0x00 {
		return h, errMalformedFrame
	}
	if h.protocol, _, err = readVarInt(r); err != nil {
		return h, errMalformedFrame
	}
	// The vanilla limit is 255 characters but Forge appends markers to the
	// address, so allow some slack before rejecting.
	if h.address, err = parseString(r, 512); err != nil {
		return h, errMalformedFrame
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return h, errMalformedFrame
	}
	h.port = binary.BigEndian.Uint16(port[:])
	if h.nextState, _, err = readVarInt(r); err != nil {
		return h, errMalformedFrame
	}
	if h.nextState != stateStatus && h.nextState != stateLogin && h.nextState != stateTransfer {
		return h, errMalformedFrame
	}
	// A plausible protocol version: 4 (1.7.2) up to a generous ceiling for
	// future versions. Zero and negative values only come from junk traffic.
	if h.protocol < 4 || h.protocol > 4096 {
		return h, errMalformedFrame
	}
	return h, nil
}

// parseLoginStart extracts the username from a Login Start packet. Trailing
// fields (UUID, signature data) vary by protocol version and are ignored.
func parseLoginStart(payload []byte) (string, error) {
	r := bytes.NewReader(payload)
	id, _, err := readVarInt(r)
	if err != nil || id != 0x00 {
		return "", errMalformedFrame
	}
	name, err := parseString(r, 32)
	if err != nil {
		return "", errMalformedFrame
	}
	if name == "" {
		return "", errMalformedFrame
	}
	return name, nil
}

func writePacket(w io.Writer, id int32, data []byte) error {
	body := appendVarInt(nil, id)
	body = append(body, data...)
	frame := appendVarInt(make([]byte, 0, 5+len(body)), int32(len(body)))
	frame = append(frame, body...)
	_, err := w.Write(frame)
	return err
}

func appendString(dst []byte, s string) []byte {
	dst = appendVarInt(dst, int32(len(s)))
	return append(dst, s...)
}

// writeLoginDisconnect kicks a client that is in the login state with the
// given message. § colour codes are passed through as-is inside the JSON text.
func writeLoginDisconnect(w io.Writer, message string) error {
	text, err := json.Marshal(map[string]string{"text": message})
	if err != nil {
		return err
	}
	return writePacket(w, 0x00, appendString(nil, string(text)))
}

// writeStatusResponse sends a status response with the given JSON document.
func writeStatusResponse(w io.Writer, statusJSON []byte) error {
	return writePacket(w, 0x00, appendString(nil, string(statusJSON)))
}

// offlineStatusJSON builds a status document served while the backend is
// unreachable. The client's protocol version is echoed so the MOTD renders
// instead of an "incompatible version" row.
func offlineStatusJSON(motd string, protocol int32) []byte {
	doc := map[string]interface{}{
		"version":     map[string]interface{}{"name": "Offline", "protocol": protocol},
		"players":     map[string]interface{}{"max": 0, "online": 0},
		"description": map[string]interface{}{"text": motd},
	}
	out, _ := json.Marshal(doc)
	return out
}

// adjustStatusJSON applies the fake online offset to a backend status document.
func adjustStatusJSON(statusJSON []byte, fakeOnline int) []byte {
	if fakeOnline <= 0 {
		return statusJSON
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(statusJSON, &doc); err != nil {
		return statusJSON
	}
	players, ok := doc["players"].(map[string]interface{})
	if !ok {
		players = map[string]interface{}{"max": 0, "online": 0}
		doc["players"] = players
	}
	online, _ := players["online"].(float64)
	players["online"] = int(online) + fakeOnline
	if max, ok := players["max"].(float64); ok && int(max) < int(online)+fakeOnline {
		players["max"] = int(online) + fakeOnline
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return statusJSON
	}
	return out
}
