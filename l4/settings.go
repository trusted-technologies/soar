package l4

import (
	"encoding/json"
	"strings"
)

// Protocol values accepted by the L4 filter. "both" installs identical rules
// for TCP and UDP on the same port.
const (
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoBoth = "both"
)

// Settings describes the L4 (network/transport) firewall rules that protect a
// single public allocation port. The Panel serialises one object per protected
// port; the daemon translates them into iptables rules in the mangle
// PREROUTING chain so that both container-published ports and the L7 proxy's
// own listeners are covered before Docker's DNAT runs.
type Settings struct {
	// Port is the public allocation port these rules protect. Zero means the
	// server's default allocation (legacy single-object documents).
	Port int `json:"port"`
	// Protocol selects which transport the rules apply to: "tcp", "udp" or
	// "both".
	Protocol string `json:"protocol"`

	// SynFlood drops TCP SYN packets from a source IP once they exceed
	// SynRate per second (with SynBurst allowance). This is the primary
	// connection-flood mitigation.
	SynFlood bool `json:"syn_flood"`
	SynRate  int  `json:"syn_rate"`
	SynBurst int  `json:"syn_burst"`

	// ConnLimitPerIP caps the number of simultaneous established TCP
	// connections a single source IP may hold. Zero disables the check.
	ConnLimitPerIP int `json:"conn_limit_per_ip"`

	// PPSLimitPerIP drops packets from a source IP once they exceed the
	// configured packets-per-second rate (with PPSBurst allowance). Applies
	// to both TCP and UDP. Zero disables the check.
	PPSLimitPerIP int `json:"pps_limit_per_ip"`
	PPSBurst      int `json:"pps_burst"`

	// DropInvalid drops packets the conntrack engine cannot associate with a
	// known flow (out-of-window, malformed, etc.).
	DropInvalid bool `json:"drop_invalid"`
	// DropFragments drops IP-fragmented packets, a common amplification and
	// evasion vector.
	DropFragments bool `json:"drop_fragments"`
	// TCPFlagSanity drops packets with illegal TCP flag combinations
	// (NULL/XMAS/SYN-FIN scans and NEW packets that are not SYN).
	TCPFlagSanity bool `json:"tcp_flag_sanity"`

	// BlockICMP drops all ICMP echo traffic to the protected IP. When it is
	// false and ICMPRate is positive, ICMP is rate-limited instead. These are
	// applied per destination IP rather than per port.
	BlockICMP bool `json:"block_icmp"`
	ICMPRate  int  `json:"icmp_rate"`

	// IPWhitelist bypasses every check for the listed source CIDRs.
	IPWhitelist []string `json:"ip_whitelist"`
	// IPBlacklist unconditionally drops the listed source CIDRs.
	IPBlacklist []string `json:"ip_blacklist"`
}

// ApplyDefaults normalises a settings document, clamping every numeric field to
// a sane range and filling reasonable defaults for a Minecraft-sized workload.
func (s Settings) ApplyDefaults() Settings {
	switch s.Protocol {
	case ProtoTCP, ProtoUDP, ProtoBoth:
	default:
		s.Protocol = ProtoBoth
	}

	if s.SynRate <= 0 {
		s.SynRate = 60
	} else if s.SynRate > 100000 {
		s.SynRate = 100000
	}
	if s.SynBurst <= 0 {
		s.SynBurst = 100
	} else if s.SynBurst > 100000 {
		s.SynBurst = 100000
	}

	if s.ConnLimitPerIP < 0 {
		s.ConnLimitPerIP = 0
	} else if s.ConnLimitPerIP > 100000 {
		s.ConnLimitPerIP = 100000
	}

	if s.PPSLimitPerIP < 0 {
		s.PPSLimitPerIP = 0
	} else if s.PPSLimitPerIP > 10000000 {
		s.PPSLimitPerIP = 10000000
	}
	if s.PPSBurst <= 0 {
		s.PPSBurst = 200
	} else if s.PPSBurst > 10000000 {
		s.PPSBurst = 10000000
	}

	if s.ICMPRate < 0 {
		s.ICMPRate = 0
	} else if s.ICMPRate > 100000 {
		s.ICMPRate = 100000
	}

	s.IPWhitelist = cleanCIDRs(s.IPWhitelist)
	s.IPBlacklist = cleanCIDRs(s.IPBlacklist)
	return s
}

func cleanCIDRs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseSettingsList turns the raw L4 document synced from the Panel into a list
// of per-port settings. It accepts both the array form and a legacy single
// object, applies defaults, fills the default port when unset and de-duplicates
// by port (last write wins).
func ParseSettingsList(raw json.RawMessage, defaultPort int) []Settings {
	if len(raw) == 0 {
		return nil
	}

	var list []Settings
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil
		}
	} else {
		var single Settings
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil
		}
		list = []Settings{single}
	}

	byPort := make(map[int]Settings, len(list))
	order := make([]int, 0, len(list))
	for _, s := range list {
		if s.Port <= 0 {
			s.Port = defaultPort
		}
		if s.Port < 1 || s.Port > 65535 {
			continue
		}
		s = s.ApplyDefaults()
		if _, ok := byPort[s.Port]; !ok {
			order = append(order, s.Port)
		}
		byPort[s.Port] = s
	}

	out := make([]Settings, 0, len(order))
	for _, p := range order {
		out = append(out, byPort[p])
	}
	return out
}
