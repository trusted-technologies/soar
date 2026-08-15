package l7proxy

// Package l7proxy provides a Minecraft-protocol-aware Layer 7 DDoS protection
// proxy. It validates every connection's handshake before forwarding to the
// backend server, and enforces per-IP rate limits and connection caps so
// handshake/join floods never reach the game server.
