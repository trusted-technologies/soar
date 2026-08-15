package l7

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/apex/log"
)

// Manager owns every active L7 proxy on this node plus the shared IP
// intelligence databases and captcha store.
type Manager struct {
	mu       sync.Mutex
	proxies  map[string]*proxy
	lists    *listService
	captcha  *captchaStore
	nodeID   string
	baseURL  string
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
			proxies: make(map[string]*proxy),
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

// Target describes where a protected allocation should listen and forward.
type Target struct {
	UUID        string
	ListenIP    string
	ListenPort  int
	BackendHost string
	BackendPort int
	Settings    Settings
}

// ParseSettings decodes the raw l7 settings object synced from the Panel and
// fills in defaults. A nil/empty document yields the default configuration.
func ParseSettings(raw json.RawMessage) Settings {
	var s Settings
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s)
	}
	return s.ApplyDefaults()
}

// Reconcile ensures a proxy for the server matches the desired state. When
// enabled is false any running proxy for the UUID is stopped.
func (m *Manager) Reconcile(uuid string, enabled bool, t Target) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, running := m.proxies[uuid]
	if !enabled {
		if running {
			existing.stop()
			delete(m.proxies, uuid)
		}
		return
	}

	listen := joinHostPort(t.ListenIP, t.ListenPort)
	be := backend{host: t.BackendHost, port: t.BackendPort}

	if running {
		if existing.listen != listen {
			// The public bind address changed; restart the listener.
			existing.stop()
			delete(m.proxies, uuid)
		} else {
			existing.update(t.Settings, be)
			return
		}
	}

	p := newProxy(uuid, m.nodeID, listen, be, t.Settings, m.lists, m.captcha, m.baseURL)
	if err := p.start(); err != nil {
		log.WithField("subsystem", "l7").WithField("server", uuid).WithField("error", err).Error("failed to start L7 proxy")
		return
	}
	m.proxies[uuid] = p
}

// Remove stops and forgets the proxy for a server (used on deletion).
func (m *Manager) Remove(uuid string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.proxies[uuid]; ok {
		p.stop()
		delete(m.proxies, uuid)
	}
}

// Stats returns the statistics snapshot for a protected server.
func (m *Manager) Stats(uuid string) (StatsSnapshot, bool) {
	if m == nil {
		return StatsSnapshot{}, false
	}
	m.mu.Lock()
	p, ok := m.proxies[uuid]
	m.mu.Unlock()
	if !ok {
		return StatsSnapshot{}, false
	}
	return p.snapshot(), true
}

// VerifyCode resolves a captcha code and marks the associated address as
// verified. It returns the server UUID that was verified.
func (m *Manager) VerifyCode(code string) (string, bool) {
	if m == nil {
		return "", false
	}
	uuid, ip, ok := m.captcha.resolve(code)
	if !ok {
		return "", false
	}
	m.mu.Lock()
	p, exists := m.proxies[uuid]
	m.mu.Unlock()
	if !exists {
		return "", false
	}
	p.verify(ip)
	return uuid, true
}

// VerifyAddress marks an explicit address as verified for a server. Used when
// the Panel passes an already-resolved uuid/ip pair.
func (m *Manager) VerifyAddress(uuid, ip string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	p, ok := m.proxies[uuid]
	m.mu.Unlock()
	if !ok {
		return false
	}
	p.verify(ip)
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
