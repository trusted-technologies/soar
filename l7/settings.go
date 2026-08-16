package l7

import (
	"regexp"
	"strings"
)

// Settings mirrors one entry of the "allocations.l7" array synced from the
// Panel for a protected allocation. All fields are optional on the wire;
// ApplyDefaults fills anything the Panel did not provide with sane values.
type Settings struct {
	// Port is the public allocation port this entry protects. Zero means the
	// server's default allocation (legacy single-object documents).
	Port int `json:"port"`
	// Preset selects the protocol-specific engine: "minecraft" (Java Edition
	// TCP filter) or "udp" (generic UDP proxy with rate limiting).
	Preset string `json:"preset"`

	// Mode is either "normal" (mitigation engages when the CPS threshold is
	// exceeded) or "always" (permanent mitigation, the "under attack" switch).
	Mode string `json:"mode"`

	// CPSThreshold is the number of new connections per second after which
	// enhanced filtering (mitigation) engages automatically.
	CPSThreshold int `json:"cps_threshold"`
	// BanSeconds is how long an offending IP stays banned.
	BanSeconds int `json:"ban_seconds"`
	// AllowSeconds is how long a verified player is remembered.
	AllowSeconds int `json:"allow_seconds"`
	// MitigationMessage is shown to players passing verification. Supports
	// Minecraft § colour codes. Limited to 200 characters.
	MitigationMessage string `json:"mitigation_message"`

	// MaxSessionsPerIP limits concurrent open connections per address.
	MaxSessionsPerIP int `json:"max_sessions_per_ip"`
	// MaxLoginsPerSecond limits login attempts per second per address (0-100).
	MaxLoginsPerSecond int `json:"max_logins_per_second"`
	// ReconnectCooldownSeconds is the delay required between a disconnect and
	// the next connection from the same address (0-60).
	ReconnectCooldownSeconds int `json:"reconnect_cooldown_seconds"`

	// BotLevel is one of off, low, medium, high, paranoid.
	BotLevel string `json:"bot_level"`
	// ExtendedChecks enables the additional verification set (ping-before-login).
	ExtendedChecks bool `json:"extended_checks"`
	// AutoMitigation automatically raises the filtering level when an attack
	// is detected via the CPS threshold.
	AutoMitigation bool `json:"auto_mitigation"`
	// CaptchaEnabled allows challenged players to verify in the browser.
	CaptchaEnabled bool `json:"captcha_enabled"`

	// VPNEnabled blocks or challenges connections from VPN/proxy/datacenter ranges.
	VPNEnabled bool `json:"vpn_enabled"`
	// VPNAction is "block" or "captcha".
	VPNAction string `json:"vpn_action"`
	// VPNMessage is the kick message for blocked VPN users.
	VPNMessage string `json:"vpn_message"`

	// ClientFilter controls which client types may join. Fabric cannot be
	// detected during the handshake, so fabric clients count as vanilla.
	ClientFilter ClientFilter `json:"client_filter"`

	// IPWhitelist contains addresses/CIDRs that always bypass every check.
	IPWhitelist []string `json:"ip_whitelist"`
	// IPBlacklist contains addresses/CIDRs that are always rejected.
	IPBlacklist []string `json:"ip_blacklist"`
	// CountryBlacklist contains ISO 3166-1 alpha-2 codes to reject.
	CountryBlacklist []string `json:"country_blacklist"`
	// ASNBlacklist contains autonomous system numbers to reject.
	ASNBlacklist []uint32 `json:"asn_blacklist"`
	// FirewallMessage is the kick message for firewall rejections.
	FirewallMessage string `json:"firewall_message"`

	// NicknameMinLength / NicknameMaxLength bound the username length.
	NicknameMinLength int `json:"nickname_min_length"`
	NicknameMaxLength int `json:"nickname_max_length"`
	// NicknameRegex, when set, must match the username (whitelist pattern).
	NicknameRegex string `json:"nickname_regex"`
	// NicknameBlacklistRegex, when set, must NOT match the username.
	NicknameBlacklistRegex string `json:"nickname_blacklist_regex"`

	// MOTDCacheSeconds is how long status (ping) responses are cached.
	MOTDCacheSeconds int `json:"motd_cache_seconds"`
	// FakeOnline is added to the real online player count in ping responses.
	FakeOnline int `json:"fake_online"`
	// OfflineMOTD is served to pings while the backend is unreachable.
	OfflineMOTD string `json:"offline_motd"`
	// OfflineKickMessage is shown to joins while the backend is unreachable.
	OfflineKickMessage string `json:"offline_kick_message"`

	// ProxyProtocol prepends a PROXY protocol v2 header on the backend
	// connection so the server sees the real player address.
	ProxyProtocol bool `json:"proxy_protocol"`

	// UDPMaxPPS limits packets per second per client flow (udp preset).
	UDPMaxPPS int `json:"udp_max_pps"`
	// UDPSessionTimeoutSeconds is how long an idle UDP flow is kept alive.
	UDPSessionTimeoutSeconds int `json:"udp_session_timeout_seconds"`
}

const (
	PresetMinecraft = "minecraft"
	PresetUDP       = "udp"
	// PresetGeyser protects a GeyserMC Bedrock (RakNet/UDP) listener. It uses
	// the UDP engine and, when ProxyProtocol is enabled, prepends a PROXY
	// protocol v2 UDP header to the first datagram of each flow so Geyser can
	// recover the player's real IP.
	PresetGeyser = "geyser"
	// PresetBedrock protects a vanilla Bedrock Dedicated Server (RakNet/UDP).
	// It uses the UDP engine in NAT mode and never emits a PROXY header: BDS
	// would treat it as a corrupt RakNet packet.
	PresetBedrock = "bedrock"
)

// isUDPPreset reports whether a preset is served by the UDP engine.
func isUDPPreset(preset string) bool {
	switch preset {
	case PresetUDP, PresetGeyser, PresetBedrock:
		return true
	default:
		return false
	}
}

type ClientFilter struct {
	Vanilla bool `json:"vanilla"`
	Forge   bool `json:"forge"`
	Fabric  bool `json:"fabric"`
}

const (
	BotLevelOff      = "off"
	BotLevelLow      = "low"
	BotLevelMedium   = "medium"
	BotLevelHigh     = "high"
	BotLevelParanoid = "paranoid"
)

// ApplyDefaults normalizes a settings struct received from the Panel.
func (s Settings) ApplyDefaults() Settings {
	switch s.Preset {
	case PresetUDP, PresetGeyser, PresetBedrock, PresetMinecraft:
	default:
		s.Preset = PresetMinecraft
	}
	// The vanilla Bedrock server cannot parse a PROXY header inside a RakNet
	// datagram, so IP forwarding is never available in this preset.
	if s.Preset == PresetBedrock {
		s.ProxyProtocol = false
	}
	if s.Mode != "always" {
		s.Mode = "normal"
	}
	if s.CPSThreshold <= 0 {
		s.CPSThreshold = 30
	}
	if s.BanSeconds <= 0 {
		s.BanSeconds = 600
	}
	if s.AllowSeconds <= 0 {
		s.AllowSeconds = 3600
	}
	if strings.TrimSpace(s.MitigationMessage) == "" {
		s.MitigationMessage = "§aVerification passed §7— reconnect to join the server."
	}
	if len([]rune(s.MitigationMessage)) > 200 {
		s.MitigationMessage = string([]rune(s.MitigationMessage)[:200])
	}
	if s.MaxSessionsPerIP <= 0 {
		s.MaxSessionsPerIP = 3
	}
	if s.MaxLoginsPerSecond < 0 {
		s.MaxLoginsPerSecond = 0
	} else if s.MaxLoginsPerSecond > 100 {
		s.MaxLoginsPerSecond = 100
	}
	if s.ReconnectCooldownSeconds < 0 {
		s.ReconnectCooldownSeconds = 0
	} else if s.ReconnectCooldownSeconds > 60 {
		s.ReconnectCooldownSeconds = 60
	}
	switch s.BotLevel {
	case BotLevelOff, BotLevelLow, BotLevelMedium, BotLevelHigh, BotLevelParanoid:
	default:
		s.BotLevel = BotLevelMedium
	}
	if s.VPNAction != "captcha" {
		s.VPNAction = "block"
	}
	if strings.TrimSpace(s.VPNMessage) == "" {
		s.VPNMessage = "§cConnections through VPN or proxy services are not allowed on this server."
	}
	if strings.TrimSpace(s.FirewallMessage) == "" {
		s.FirewallMessage = "§cYou are not allowed to join this server."
	}
	// If every client type is disabled treat the filter as "allow all"; a
	// filter that rejects everyone is never what the user intended.
	if !s.ClientFilter.Vanilla && !s.ClientFilter.Forge && !s.ClientFilter.Fabric {
		s.ClientFilter = ClientFilter{Vanilla: true, Forge: true, Fabric: true}
	}
	if s.NicknameMinLength <= 0 {
		s.NicknameMinLength = 1
	}
	if s.NicknameMaxLength <= 0 || s.NicknameMaxLength > 16 {
		s.NicknameMaxLength = 16
	}
	if s.NicknameMinLength > s.NicknameMaxLength {
		s.NicknameMinLength = s.NicknameMaxLength
	}
	if s.MOTDCacheSeconds <= 0 {
		s.MOTDCacheSeconds = 10
	} else if s.MOTDCacheSeconds > 300 {
		s.MOTDCacheSeconds = 300
	}
	if s.FakeOnline < 0 {
		s.FakeOnline = 0
	}
	if strings.TrimSpace(s.OfflineMOTD) == "" {
		s.OfflineMOTD = "§cServer is offline"
	}
	if strings.TrimSpace(s.OfflineKickMessage) == "" {
		s.OfflineKickMessage = "§cThe server is currently offline. Try again in a moment."
	}
	if s.UDPMaxPPS <= 0 {
		s.UDPMaxPPS = 2000
	} else if s.UDPMaxPPS > 1000000 {
		s.UDPMaxPPS = 1000000
	}
	if s.UDPSessionTimeoutSeconds <= 0 {
		s.UDPSessionTimeoutSeconds = 60
	} else if s.UDPSessionTimeoutSeconds > 600 {
		s.UDPSessionTimeoutSeconds = 600
	}
	return s
}

// compiledRules holds pre-parsed versions of the rule settings so that the hot
// path never parses CIDRs or compiles regular expressions per connection.
type compiledRules struct {
	whitelist      *cidrSet
	blacklist      *cidrSet
	countries      map[string]struct{}
	asns           map[uint32]struct{}
	nickWhitelist  *regexp.Regexp
	nickBlacklist  *regexp.Regexp
	needsGeo       bool
	needsASN       bool
	needsVPN       bool
}

func compileRules(s Settings) *compiledRules {
	r := &compiledRules{
		whitelist: newCidrSet(s.IPWhitelist),
		blacklist: newCidrSet(s.IPBlacklist),
		countries: make(map[string]struct{}, len(s.CountryBlacklist)),
		asns:      make(map[uint32]struct{}, len(s.ASNBlacklist)),
	}
	for _, c := range s.CountryBlacklist {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) == 2 {
			r.countries[c] = struct{}{}
		}
	}
	for _, a := range s.ASNBlacklist {
		if a > 0 {
			r.asns[a] = struct{}{}
		}
	}
	if p := strings.TrimSpace(s.NicknameRegex); p != "" {
		if re, err := regexp.Compile(p); err == nil {
			r.nickWhitelist = re
		}
	}
	if p := strings.TrimSpace(s.NicknameBlacklistRegex); p != "" {
		if re, err := regexp.Compile(p); err == nil {
			r.nickBlacklist = re
		}
	}
	r.needsGeo = len(r.countries) > 0
	r.needsASN = len(r.asns) > 0
	r.needsVPN = s.VPNEnabled
	return r
}
