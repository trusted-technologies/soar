package l7proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Minecraft next-state constants from the handshake packet.
const (
	StateStatus = 1
	StateLogin  = 2
)

// Handshake holds the decoded Minecraft handshake packet fields.
type Handshake struct {
	ProtocolVersion int
	ServerAddress   string
	ServerPort      uint16
	NextState       int
}

// ReadHandshake reads the first Minecraft packet from conn, decodes it as a
// handshake (0x00), and returns both the parsed fields and the raw bytes so
// the caller can replay them verbatim to the backend.
func ReadHandshake(conn net.Conn) (Handshake, []byte, error) {
	// Read the entire first packet (length-prefixed VarInt frame).
	pktLen, lenBytes, err := readVarInt(conn)
	if err != nil {
		return Handshake{}, nil, fmt.Errorf("l7proxy: read packet length: %w", err)
	}
	if pktLen < 1 || pktLen > 4096 {
		return Handshake{}, nil, fmt.Errorf("l7proxy: packet length out of range: %d", pktLen)
	}

	body := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return Handshake{}, nil, fmt.Errorf("l7proxy: read packet body: %w", err)
	}

	raw := append(lenBytes, body...)
	r := bytes.NewReader(body)

	// Packet ID must be 0x00 (handshake).
	packetID, _, err := readVarIntReader(r)
	if err != nil || packetID != 0x00 {
		return Handshake{}, nil, fmt.Errorf("l7proxy: unexpected packet id: %d", packetID)
	}

	var hs Handshake

	hs.ProtocolVersion, _, err = readVarIntReader(r)
	if err != nil {
		return Handshake{}, nil, fmt.Errorf("l7proxy: read protocol version: %w", err)
	}

	hs.ServerAddress, err = readString(r)
	if err != nil {
		return Handshake{}, nil, fmt.Errorf("l7proxy: read server address: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &hs.ServerPort); err != nil {
		return Handshake{}, nil, fmt.Errorf("l7proxy: read server port: %w", err)
	}

	hs.NextState, _, err = readVarIntReader(r)
	if err != nil {
		return Handshake{}, nil, fmt.Errorf("l7proxy: read next state: %w", err)
	}

	return hs, raw, nil
}

// readVarInt reads a Minecraft VarInt (up to 5 bytes) from a net.Conn and
// returns both the value and the raw bytes consumed.
func readVarInt(r io.Reader) (int, []byte, error) {
	var result int
	var shift uint
	var raw []byte
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
		b := buf[0]
		raw = append(raw, b)
		result |= int(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, nil, fmt.Errorf("l7proxy: varint too long")
		}
	}
	return result, raw, nil
}

// readVarIntReader reads a VarInt from a bytes.Reader.
func readVarIntReader(r *bytes.Reader) (int, []byte, error) {
	var result int
	var shift uint
	var raw []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		raw = append(raw, b)
		result |= int(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, nil, fmt.Errorf("l7proxy: varint too long")
		}
	}
	return result, raw, nil
}

// readString reads a Minecraft-prefixed string (VarInt length + UTF-8 bytes).
func readString(r *bytes.Reader) (string, error) {
	length, _, err := readVarIntReader(r)
	if err != nil {
		return "", err
	}
	if length < 0 || length > 32767 {
		return "", fmt.Errorf("l7proxy: string length out of range: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}
