package l4

import (
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"sync"

	"github.com/apex/log"
)

var errUnavailable = errors.New("iptables unavailable")

var (
	defaultManager *Manager
	defaultOnce    sync.Once
)

// Target describes one protected allocation port for a server. IP is the node's
// public address the port is reachable on.
type Target struct {
	IP       string
	Port     int
	Settings Settings
}

// chainInfo records a per-target chain so stats and teardown can find it.
type chainInfo struct {
	port  int
	proto string
	chain string
}

// serverState remembers everything installed for a single server so a later
// reconcile or removal can tear it down precisely.
type serverState struct {
	chains    []chainInfo
	baseRules [][]string
	ips       map[string]struct{}
}

// Manager owns the node's L4 iptables state. All mutations are serialised.
type Manager struct {
	mu      sync.Mutex
	ipt     *iptables
	enabled bool

	servers map[string]*serverState

	// icmpByIP tracks each server's requested ICMP policy per destination IP.
	// ICMP has no port, and on most nodes every server shares one public IP,
	// so the policy is aggregated across servers and (re)programmed as a
	// single rule set per IP.
	icmpByIP    map[string]map[string]Settings
	icmpApplied map[string][][]string
}

// Configure initialises the global L4 manager and resets the node's L4 chains
// to a clean slate. Safe to call when iptables is missing: the manager simply
// becomes a no-op.
func Configure() *Manager {
	defaultOnce.Do(func() {
		m := &Manager{
			ipt:         newIPTables(),
			servers:     make(map[string]*serverState),
			icmpByIP:    make(map[string]map[string]Settings),
			icmpApplied: make(map[string][][]string),
		}
		if !m.ipt.available() {
			log.WithField("subsystem", "l4").Warn("iptables binary not found; L4 protection is disabled on this node")
			defaultManager = m
			return
		}
		m.enabled = true
		m.reset()
		defaultManager = m
		log.WithField("subsystem", "l4").Info("L4 protection initialised")
	})
	return defaultManager
}

// Default returns the global manager, or nil if Configure was never called.
func Default() *Manager { return defaultManager }

// reset rebuilds the base chain and the PREROUTING jump, wiping any child
// chains left over from a previous daemon run.
func (m *Manager) reset() {
	if err := m.ipt.ensureChain(baseChain); err != nil {
		log.WithField("subsystem", "l4").WithField("error", err).Warn("failed to create L4 base chain")
		return
	}
	m.ipt.tryRun("-F", baseChain)
	for _, c := range m.listChildChains() {
		m.ipt.dropChain(c)
	}
	if err := m.ipt.insertRule(parentChain, []string{"-j", baseChain}); err != nil {
		log.WithField("subsystem", "l4").WithField("error", err).Warn("failed to hook L4 base chain into PREROUTING")
	}
}

// listChildChains returns every SL4* chain currently defined in the mangle
// table by parsing "iptables -S".
func (m *Manager) listChildChains() []string {
	out, err := m.ipt.run("-S")
	if err != nil {
		return nil
	}
	var chains []string
	for _, line := range splitLines(out) {
		if len(line) > 3 && line[:3] == "-N " {
			name := line[3:]
			if len(name) >= 3 && name[:3] == "SL4" {
				chains = append(chains, name)
			}
		}
	}
	return chains
}

// ReconcileServer installs L4 rules for the given targets, replacing any rules
// previously installed for this server. An empty target list removes them.
func (m *Manager) ReconcileServer(uuid string, targets []Target) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return
	}

	touched := m.teardownLocked(uuid)

	if len(targets) == 0 {
		for ip := range touched {
			m.reprogramICMP(ip)
		}
		return
	}

	st := &serverState{ips: make(map[string]struct{})}
	for _, t := range targets {
		if t.IP == "" || t.Port < 1 || t.Port > 65535 {
			continue
		}
		st.ips[t.IP] = struct{}{}
		touched[t.IP] = struct{}{}

		for _, proto := range protosFor(t.Settings.Protocol) {
			chain := chainName(uuid, t.Port, proto)
			m.ipt.dropChain(chain)
			if err := m.ipt.ensureChain(chain); err != nil {
				log.WithField("subsystem", "l4").WithField("error", err).Warn("failed to create L4 chain")
				continue
			}
			m.fillChain(chain, proto, t.Settings)
			jump := []string{"-d", t.IP, "-p", proto, "--dport", strconv.Itoa(t.Port), "-j", chain}
			if err := m.ipt.ensureRule(baseChain, jump); err != nil {
				log.WithField("subsystem", "l4").WithField("error", err).Warn("failed to install L4 jump rule")
				m.ipt.dropChain(chain)
				continue
			}
			st.chains = append(st.chains, chainInfo{port: t.Port, proto: proto, chain: chain})
			st.baseRules = append(st.baseRules, jump)
		}

		// Record the per-server ICMP policy for this destination IP.
		if m.icmpByIP[t.IP] == nil {
			m.icmpByIP[t.IP] = make(map[string]Settings)
		}
		m.icmpByIP[t.IP][uuid] = t.Settings
	}

	m.servers[uuid] = st
	for ip := range touched {
		m.reprogramICMP(ip)
	}
}

// Remove tears down all L4 rules for a server (used when it is deleted).
func (m *Manager) Remove(uuid string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return
	}
	touched := m.teardownLocked(uuid)
	for ip := range touched {
		m.reprogramICMP(ip)
	}
}

// teardownLocked removes the port chains/jumps and ICMP bookkeeping for a
// server, returning the set of destination IPs whose ICMP policy must be
// recomputed by the caller.
func (m *Manager) teardownLocked(uuid string) map[string]struct{} {
	touched := make(map[string]struct{})
	if st, ok := m.servers[uuid]; ok {
		for _, r := range st.baseRules {
			m.ipt.deleteRule(baseChain, r)
		}
		for _, c := range st.chains {
			m.ipt.dropChain(c.chain)
		}
		for ip := range st.ips {
			touched[ip] = struct{}{}
		}
		delete(m.servers, uuid)
	}
	for ip, byUUID := range m.icmpByIP {
		if _, ok := byUUID[uuid]; ok {
			delete(byUUID, uuid)
			touched[ip] = struct{}{}
			if len(byUUID) == 0 {
				delete(m.icmpByIP, ip)
			}
		}
	}
	return touched
}

// reprogramICMP recomputes and reinstalls the aggregated ICMP rule set for a
// destination IP based on every server's requested policy. Block wins over
// rate-limit; the strictest positive rate is used otherwise.
func (m *Manager) reprogramICMP(ip string) {
	for _, r := range m.icmpApplied[ip] {
		m.ipt.deleteRule(baseChain, r)
	}
	delete(m.icmpApplied, ip)

	block := false
	rate := 0
	for _, s := range m.icmpByIP[ip] {
		if s.BlockICMP {
			block = true
		}
		rate = mergeRate(rate, s.ICMPRate)
	}

	rules := icmpRules(ip, block, rate)
	for _, r := range rules {
		if err := m.ipt.ensureRule(baseChain, r); err != nil {
			log.WithField("subsystem", "l4").WithField("error", err).Warn("failed to install L4 ICMP rule")
			continue
		}
		m.icmpApplied[ip] = append(m.icmpApplied[ip], r)
	}
}

// fillChain writes the ordered rule set for a single protected port into its
// dedicated chain. Whitelisted sources RETURN early; everything else is subject
// to the configured drops and rate limits.
func (m *Manager) fillChain(chain, proto string, s Settings) {
	add := func(rule ...string) {
		if _, err := m.ipt.run(append([]string{"-A", chain}, rule...)...); err != nil {
			log.WithField("subsystem", "l4").WithField("chain", chain).WithField("error", err).Debug("failed to append L4 rule")
		}
	}
	comment := func(reason string) []string {
		return []string{"-m", "comment", "--comment", "l4:" + reason}
	}

	for _, cidr := range s.IPWhitelist {
		add(append(append([]string{"-s", cidr}, comment("whitelist")...), "-j", "RETURN")...)
	}
	for _, cidr := range s.IPBlacklist {
		add(append(append([]string{"-s", cidr}, comment("blacklist")...), "-j", "DROP")...)
	}

	if s.DropInvalid {
		add(append(append([]string{"-m", "conntrack", "--ctstate", "INVALID"}, comment("invalid")...), "-j", "DROP")...)
	}
	if s.DropFragments {
		add(append(append([]string{"-f"}, comment("fragment")...), "-j", "DROP")...)
	}

	if proto == ProtoTCP {
		if s.TCPFlagSanity {
			add(append(append([]string{"-p", "tcp", "!", "--syn", "-m", "conntrack", "--ctstate", "NEW"}, comment("newnosyn")...), "-j", "DROP")...)
			add(append(append([]string{"-p", "tcp", "--tcp-flags", "ALL", "NONE"}, comment("null")...), "-j", "DROP")...)
			add(append(append([]string{"-p", "tcp", "--tcp-flags", "ALL", "ALL"}, comment("xmas")...), "-j", "DROP")...)
			add(append(append([]string{"-p", "tcp", "--tcp-flags", "ALL", "FIN,PSH,URG"}, comment("xmas")...), "-j", "DROP")...)
			add(append(append([]string{"-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN"}, comment("synfin")...), "-j", "DROP")...)
			add(append(append([]string{"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST"}, comment("synrst")...), "-j", "DROP")...)
		}
		if s.SynFlood {
			name := hashName("s", chain)
			add(append(append([]string{
				"-p", "tcp", "--syn",
				"-m", "hashlimit",
				"--hashlimit-name", name,
				"--hashlimit-mode", "srcip",
				"--hashlimit-above", fmt.Sprintf("%d/sec", s.SynRate),
				"--hashlimit-burst", strconv.Itoa(s.SynBurst),
			}, comment("synflood")...), "-j", "DROP")...)
		}
		if s.ConnLimitPerIP > 0 {
			add(append(append([]string{
				"-p", "tcp", "--syn",
				"-m", "connlimit",
				"--connlimit-above", strconv.Itoa(s.ConnLimitPerIP),
				"--connlimit-mask", "32",
			}, comment("connlimit")...), "-j", "DROP")...)
		}
	}

	if s.PPSLimitPerIP > 0 {
		name := hashName("p", chain)
		add(append(append([]string{
			"-m", "hashlimit",
			"--hashlimit-name", name,
			"--hashlimit-mode", "srcip",
			"--hashlimit-above", fmt.Sprintf("%d/sec", s.PPSLimitPerIP),
			"--hashlimit-burst", strconv.Itoa(s.PPSBurst),
		}, comment("pps")...), "-j", "DROP")...)
	}
}

// icmpRules builds the aggregated ICMP rule set for one destination IP.
func icmpRules(ip string, block bool, rate int) [][]string {
	comment := []string{"-m", "comment", "--comment", "l4:icmp"}
	if block {
		return [][]string{append(append([]string{"-d", ip, "-p", "icmp"}, comment...), "-j", "DROP")}
	}
	if rate > 0 {
		name := fmt.Sprintf("i%08X", crc32.ChecksumIEEE([]byte(ip)))
		if len(name) > 15 {
			name = name[:15]
		}
		return [][]string{append(append([]string{
			"-d", ip, "-p", "icmp",
			"-m", "hashlimit",
			"--hashlimit-name", name,
			"--hashlimit-mode", "srcip",
			"--hashlimit-above", fmt.Sprintf("%d/sec", rate),
			"--hashlimit-burst", strconv.Itoa(rate),
		}, comment...), "-j", "DROP")}
	}
	return nil
}

// protosFor expands the protocol selector into the concrete protocols to
// program.
func protosFor(protocol string) []string {
	switch protocol {
	case ProtoTCP:
		return []string{ProtoTCP}
	case ProtoUDP:
		return []string{ProtoUDP}
	default:
		return []string{ProtoTCP, ProtoUDP}
	}
}

// mergeRate returns the strictest (smallest) positive rate, or the other value
// when one is unset (0 == unlimited).
func mergeRate(a, b int) int {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if l := len(line); l > 0 && line[l-1] == '\r' {
				line = line[:l-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
