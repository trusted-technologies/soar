package l4

import (
	"sort"
	"strconv"
	"strings"
)

// StatsSnapshot summarises the packet counters iptables tracks for one
// protected port. Reasons maps each rule category (synflood, pps, invalid, ...)
// to the number of packets it matched.
type StatsSnapshot struct {
	Enabled        bool              `json:"enabled"`
	Port           int               `json:"port"`
	Protocol       string            `json:"protocol"`
	PacketsDropped uint64            `json:"packets_dropped"`
	PacketsAllowed uint64            `json:"packets_allowed"`
	Reasons        map[string]uint64 `json:"reasons"`
}

// Stats returns the counters for a single protected port, or nil when the
// server has no L4 rules for it.
func (m *Manager) Stats(uuid string, port int) *StatsSnapshot {
	all := m.StatsAll(uuid)
	for i := range all {
		if all[i].Port == port {
			return &all[i]
		}
	}
	return nil
}

// StatsAll returns one snapshot per protected port for a server, aggregating
// the TCP and UDP chains that back each port.
func (m *Manager) StatsAll(uuid string) []StatsSnapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	st, ok := m.servers[uuid]
	enabled := m.enabled
	// Copy the chain list so counters can be read without holding the lock.
	var chains []chainInfo
	if ok {
		chains = append(chains, st.chains...)
	}
	m.mu.Unlock()

	if !enabled || len(chains) == 0 {
		return nil
	}

	type agg struct {
		protos  map[string]struct{}
		reasons map[string]uint64
	}
	byPort := make(map[int]*agg)
	order := make([]int, 0)

	for _, ci := range chains {
		a := byPort[ci.port]
		if a == nil {
			a = &agg{protos: make(map[string]struct{}), reasons: make(map[string]uint64)}
			byPort[ci.port] = a
			order = append(order, ci.port)
		}
		a.protos[ci.proto] = struct{}{}
		for reason, pkts := range m.readChainCounters(ci.chain) {
			a.reasons[reason] += pkts
		}
	}

	sort.Ints(order)
	out := make([]StatsSnapshot, 0, len(order))
	for _, port := range order {
		a := byPort[port]
		snap := StatsSnapshot{
			Enabled:  true,
			Port:     port,
			Protocol: protocolLabel(a.protos),
			Reasons:  a.reasons,
		}
		for reason, pkts := range a.reasons {
			if reason == "whitelist" {
				snap.PacketsAllowed += pkts
			} else {
				snap.PacketsDropped += pkts
			}
		}
		out = append(out, snap)
	}
	return out
}

// readChainCounters parses "iptables -L <chain> -nvx" and returns the packet
// count for each rule keyed by its l4:<reason> comment.
func (m *Manager) readChainCounters(chain string) map[string]uint64 {
	out := make(map[string]uint64)
	raw, err := m.ipt.run("-L", chain, "-n", "-v", "-x")
	if err != nil {
		return out
	}
	for _, line := range splitLines(raw) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkts, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		reason := commentReason(line)
		if reason == "" {
			continue
		}
		out[reason] += pkts
	}
	return out
}

// commentReason extracts the "<reason>" from a rule line's /* l4:<reason> */
// comment, or "" when absent.
func commentReason(line string) string {
	const tag = "l4:"
	i := strings.Index(line, tag)
	if i < 0 {
		return ""
	}
	rest := line[i+len(tag):]
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		if c == ' ' || c == '\t' || c == '*' || c == '/' {
			return rest[:j]
		}
	}
	return rest
}

func protocolLabel(protos map[string]struct{}) string {
	_, tcp := protos[ProtoTCP]
	_, udp := protos[ProtoUDP]
	switch {
	case tcp && udp:
		return ProtoBoth
	case tcp:
		return ProtoTCP
	case udp:
		return ProtoUDP
	default:
		return ""
	}
}
