package l7

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

// buildHandshake constructs a clean handshake packet toward the backend.
func buildHandshake(protocol int32, host string, port uint16, nextState int32) []byte {
	body := appendVarInt(nil, 0x00) // packet id
	body = appendVarInt(body, protocol)
	body = appendString(body, host)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	body = append(body, p[:]...)
	body = appendVarInt(body, nextState)
	frame := appendVarInt(make([]byte, 0, 5+len(body)), int32(len(body)))
	return append(frame, body...)
}

// extractStatusJSON reads the length-prefixed status string from the remainder
// of a backend status response packet (after the packet id byte).
func extractStatusJSON(data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	l, _, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	if l < 0 || int(l) > r.Len() {
		return nil, errMalformedFrame
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// proxyProtocolV2Header builds a PROXY protocol v2 header describing the real
// client connection so a backend that understands it can log the true source
// address. Returns nil if the addresses are not usable TCP endpoints.
func proxyProtocolV2Header(src, dst net.Addr) []byte {
	srcTCP, ok1 := src.(*net.TCPAddr)
	dstTCP, ok2 := dst.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil
	}
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	out := make([]byte, 0, 28)
	out = append(out, sig...)
	out = append(out, 0x21) // version 2, command PROXY

	src4 := srcTCP.IP.To4()
	dst4 := dstTCP.IP.To4()
	if src4 != nil && dst4 != nil {
		out = append(out, 0x11) // TCP over IPv4
		out = append(out, 0x00, 12)
		out = append(out, src4...)
		out = append(out, dst4...)
		var ports [4]byte
		binary.BigEndian.PutUint16(ports[0:2], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(ports[2:4], uint16(dstTCP.Port))
		out = append(out, ports[:]...)
		return out
	}

	src16 := srcTCP.IP.To16()
	dst16 := dstTCP.IP.To16()
	if src16 == nil || dst16 == nil {
		return nil
	}
	out = append(out, 0x21) // TCP over IPv6
	out = append(out, 0x00, 36)
	out = append(out, src16...)
	out = append(out, dst16...)
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], uint16(srcTCP.Port))
	binary.BigEndian.PutUint16(ports[2:4], uint16(dstTCP.Port))
	out = append(out, ports[:]...)
	return out
}
