package l7

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/apex/log"
)

// portProxy is implemented by the per-preset protection engines (the Minecraft
// TCP filter and the generic UDP proxy).
type portProxy interface {
	start() error
	stop()
	update(Settings, backend)
	snapshot() StatsSnapshot
	verify(ip string)
	listenAddr() string
	presetName() string
}

// Manager owns every active L7 proxy on this node plus the shared IP
// intelligence databases and captcha store. Proxies are grouped per server
// UUID and keyed by their public port.
type Manager struct {
	mu      sync.Mutex
	proxies map[string]map[int]portProxy
	lists   *listService
	captcha *captchaStore
	nodeID  string
	baseURL string
}

var (
	defaultManager *Manager
	defaultOnce    sync.Once
)

// Configure initializes the shared manager. dataDir is the node root directory,
// nodeID identifies this node, and baseURL is the public origin of the Panel
// (used to build captcha links, e.g. https://stacker.host).
func Configure(dataDir, nodeID, baseURL string) *Manager {
	defaultOnce.Do(func() {
		defaultManager = &Manager{
			proxies: make(map[string]map[int]portProxy),
			lists:   newListService(filepath.Join(dataDir, "l7")),
			captcha: newCaptchaStore(),
			nodeID:  nodeID,
			baseURL: strings.TrimRight(baseURL, "/"),
		}
	})
	return defaultManager
}

// Default returns the configured manager, or nil if Configure was never called.
func Default() *Manager {
	return defaultManager
}

// Target describes where one protected allocation should listen and forward.
type Target struct {
	UUID        string
	ListenIP    string
	ListenPort  int
	BackendHost string
	BackendPort int
	Settings    Settings
}

// ParseSettingsList decodes the "allocations.l7" document synced from the
// Panel. The current wire format is an array of per-port settings objects; a
// legacy single object (protecting the default allocation) is still accepted.
// Entries without a port fall back to defaultPort; duplicate ports keep the
// first entry.
func ParseSettingsList(raw json.RawMessage, defaultPort int) []Settings {
	var entries []Settings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &entries); err != nil {
			var single Settings
			if err := json.Unmarshal(raw, &single); err == nil {
				entries = []Settings{single}
			}
		}
	}
	out := make([]Settings, 0, len(entries))
	seen := make(map[int]struct{}, len(entries))
	for _, e := range entries {
		s := e.ApplyDefaults()
		if s.Port <= 0 || s.Port > 65535 {
			s.Port = defaultPort
		}
		if s.Port <= 0 || s.Port > 65535 {
			continue
		}
		if _, dup := seen[s.Port]; dup {
			continue
		}
		seen[s.Port] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ReconcileServer brings the set of proxies for a server in line with the
// desired targets. Proxies for ports that are no longer listed are stopped;
// an empty target list stops everything for the server.
func (m *Manager) ReconcileServer(uuid string, targets []Target) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.proxies[uuid]
	desired := make(map[int]Target, len(targets))
	for _, t := range targets {
		if t.ListenPort >= 1 && t.ListenPort <= 65535 {
			desired[t.ListenPort] = t
		}
	}

	for port, p := range current {
		if _, keep := desired[port]; !keep {
			p.stop()
			delete(current, port)
		}
	}

	for port, t := range desired {
		listen := joinHostPort(t.ListenIP, port)
		be := backend{host: t.BackendHost, port: t.BackendPort}
		t.Settings.Port = port

		if p, ok := current[port]; ok {
			// A changed bind address or preset requires a listener restart;
			// plain settings changes are applied in place.
			if p.listenAddr() == listen && p.presetName() == t.Settings.Preset {
				p.update(t.Settings, be)
				continue
			}
			p.stop()
			delete(current, port)
		}

		var p portProxy
		if t.Settings.Preset == PresetUDP {
			p = newUDPProxy(uuid, listen, be, t.Settings, m.lists)
		} else {
			p = newProxy(uuid, m.nodeID, listen, be, t.Settings, m.lists, m.captcha, m.baseURL)
		}
		if err := p.start(); err != nil {
			log.WithField("subsystem", "l7").WithField("server", uuid).WithField("port", port).WithField("error", err).Error("failed to start L7 proxy")
			continue
		}
		if current == nil {
			current = make(map[int]portProxy)
			m.proxies[uuid] = current
		}
		current[port] = p
	}

	if len(current) == 0 {
		delete(m.proxies, uuid)
	}
}

// Remove stops and forgets every proxy for a server (used on deletion).
func (m *Manager) Remove(uuid string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, p := range m.proxies[uuid] {
		p.stop()
		delete(m.proxies[uuid], port)
	}
	delete(m.proxies, uuid)
}

// Stats returns the statistics snapshot for one protected port of a server.
func (m *Manager) Stats(uuid string, port int) (StatsSnapshot, bool) {
	if m == nil {
		return StatsSnapshot{}, false
	}
	m.mu.Lock()
	p, ok := m.proxies[uuid][port]
	m.mu.Unlock()
	if !ok {
		return StatsSnapshot{}, false
	}
	return p.snapshot(), true
}

// StatsAll returns snapshots for every protected port of a server.
func (m *Manager) StatsAll(uuid string) []StatsSnapshot {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	group := m.proxies[uuid]
	proxies := make([]portProxy, 0, len(group))
	for _, p := range group {
		proxies = append(proxies, p)
	}
	m.mu.Unlock()
	out := make([]StatsSnapshot, 0, len(proxies))
	for _, p := range proxies {
		out = append(out, p.snapshot())
	}
	return out
}

// VerifyCode resolves a captcha code and marks the associated address as
// verified on every proxy of that server. It returns the server UUID.
func (m *Manager) VerifyCode(code string) (string, bool) {
	if m == nil {
		return "", false
	}
	uuid, ip, ok := m.captcha.resolve(code)
	if !ok {
		return "", false
	}
	return uuid, m.VerifyAddress(uuid, ip)
}

// VerifyAddress marks an explicit address as verified for a server. Used when
// the Panel passes an already-resolved uuid/ip pair.
func (m *Manager) VerifyAddress(uuid, ip string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	group := m.proxies[uuid]
	proxies := make([]portProxy, 0, len(group))
	for _, p := range group {
		proxies = append(proxies, p)
	}
	m.mu.Unlock()
	if len(proxies) == 0 {
		return false
	}
	for _, p := range proxies {
		p.verify(ip)
	}
	return true
}

func joinHostPort(ip string, port int) string {
	if ip == "" || ip == "0.0.0.0" {
		return ":" + strconv.Itoa(port)
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}
