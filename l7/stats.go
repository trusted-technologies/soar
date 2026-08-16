package l7

import (
	"sync"
	"sync/atomic"
)

// Block reasons reported in statistics and activity logs.
const (
	reasonBanned            = "banned"
	reasonFirewall          = "firewall"
	reasonCountry           = "country"
	reasonASN               = "asn"
	reasonVPN               = "vpn"
	reasonSessionLimit      = "session_limit"
	reasonLoginRate         = "login_rate"
	reasonReconnectCooldown = "reconnect_cooldown"
	reasonStatusFlood       = "status_flood"
	reasonProtocol          = "protocol_violation"
	reasonLegacyPing        = "legacy_ping"
	reasonNickname          = "nickname"
	reasonClientType        = "client_type"
	reasonChallenge         = "challenge"
	reasonCaptcha           = "captcha"
	reasonBackendDown       = "backend_down"
	reasonRateLimit         = "rate_limit"
	reasonMitigation        = "mitigation"
)

type stats struct {
	total   atomic.Uint64
	passed  atomic.Uint64
	pings   atomic.Uint64
	blocked atomic.Uint64

	mu      sync.Mutex
	reasons map[string]uint64
}

func newStats() *stats {
	return &stats{reasons: make(map[string]uint64)}
}

func (s *stats) block(reason string) {
	s.blocked.Add(1)
	s.mu.Lock()
	s.reasons[reason]++
	s.mu.Unlock()
}

// StatsSnapshot is the JSON document returned to the Panel for one protected
// allocation.
type StatsSnapshot struct {
	Enabled          bool              `json:"enabled"`
	Port             int               `json:"port"`
	Preset           string            `json:"preset"`
	Mode             string            `json:"mode"`
	Mitigation       bool              `json:"mitigation"`
	CPS              int               `json:"cps"`
	TotalConnections uint64            `json:"total_connections"`
	Passed           uint64            `json:"passed"`
	Pings            uint64            `json:"pings"`
	Blocked          uint64            `json:"blocked"`
	BlockedReasons   map[string]uint64 `json:"blocked_reasons"`
	VerifiedIPs      int               `json:"verified_ips"`
	BannedIPs        int               `json:"banned_ips"`
	TrackedIPs       int               `json:"tracked_ips"`
}

func (s *stats) snapshot() (out StatsSnapshot) {
	out.TotalConnections = s.total.Load()
	out.Passed = s.passed.Load()
	out.Pings = s.pings.Load()
	out.Blocked = s.blocked.Load()
	out.BlockedReasons = make(map[string]uint64)
	s.mu.Lock()
	for k, v := range s.reasons {
		out.BlockedReasons[k] = v
	}
	s.mu.Unlock()
	return out
}
