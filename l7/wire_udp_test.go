package l7

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

var ppv2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func TestProxyProtocolV2HeaderUDPv4(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 54321}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 19132}

	hdr := proxyProtocolV2HeaderUDP(src, dst)
	if hdr == nil {
		t.Fatal("expected header, got nil")
	}
	if len(hdr) != 28 {
		t.Fatalf("IPv4 UDP header must be 28 bytes, got %d", len(hdr))
	}
	if !bytes.Equal(hdr[:12], ppv2Signature) {
		t.Fatalf("bad signature: %x", hdr[:12])
	}
	if hdr[12] != 0x21 {
		t.Fatalf("ver_cmd must be 0x21, got 0x%02x", hdr[12])
	}
	if hdr[13] != 0x12 {
		t.Fatalf("fam_proto must be 0x12 (IPv4+UDP), got 0x%02x", hdr[13])
	}
	if alen := binary.BigEndian.Uint16(hdr[14:16]); alen != 12 {
		t.Fatalf("address length must be 12, got %d", alen)
	}
	if !bytes.Equal(hdr[16:20], src.IP.To4()) {
		t.Fatalf("src ip mismatch: %x", hdr[16:20])
	}
	if !bytes.Equal(hdr[20:24], dst.IP.To4()) {
		t.Fatalf("dst ip mismatch: %x", hdr[20:24])
	}
	if p := binary.BigEndian.Uint16(hdr[24:26]); p != 54321 {
		t.Fatalf("src port must be network byte order 54321, got %d", p)
	}
	if p := binary.BigEndian.Uint16(hdr[26:28]); p != 19132 {
		t.Fatalf("dst port must be network byte order 19132, got %d", p)
	}
}

func TestProxyProtocolV2HeaderUDPv6(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000}
	dst := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 19132}

	hdr := proxyProtocolV2HeaderUDP(src, dst)
	if hdr == nil {
		t.Fatal("expected header, got nil")
	}
	if len(hdr) != 52 {
		t.Fatalf("IPv6 UDP header must be 52 bytes, got %d", len(hdr))
	}
	if !bytes.Equal(hdr[:12], ppv2Signature) {
		t.Fatalf("bad signature: %x", hdr[:12])
	}
	if hdr[12] != 0x21 {
		t.Fatalf("ver_cmd must be 0x21, got 0x%02x", hdr[12])
	}
	if hdr[13] != 0x22 {
		t.Fatalf("fam_proto must be 0x22 (IPv6+UDP), got 0x%02x", hdr[13])
	}
	if alen := binary.BigEndian.Uint16(hdr[14:16]); alen != 36 {
		t.Fatalf("address length must be 36, got %d", alen)
	}
	if !bytes.Equal(hdr[16:32], src.IP.To16()) {
		t.Fatalf("src ip mismatch: %x", hdr[16:32])
	}
	if !bytes.Equal(hdr[32:48], dst.IP.To16()) {
		t.Fatalf("dst ip mismatch: %x", hdr[32:48])
	}
	if p := binary.BigEndian.Uint16(hdr[48:50]); p != 40000 {
		t.Fatalf("src port mismatch, got %d", p)
	}
	if p := binary.BigEndian.Uint16(hdr[50:52]); p != 19132 {
		t.Fatalf("dst port mismatch, got %d", p)
	}
}

func TestBedrockPresetForcesProxyProtocolOff(t *testing.T) {
	s := Settings{Preset: PresetBedrock, ProxyProtocol: true}.ApplyDefaults()
	if s.ProxyProtocol {
		t.Fatal("bedrock preset must force proxy_protocol off")
	}
	if !isUDPPreset(PresetGeyser) || !isUDPPreset(PresetBedrock) || !isUDPPreset(PresetUDP) {
		t.Fatal("geyser/bedrock/udp must all be UDP presets")
	}
	if isUDPPreset(PresetMinecraft) {
		t.Fatal("minecraft must not be a UDP preset")
	}
}
