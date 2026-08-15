package httpgateway

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"golang.org/x/crypto/acme/autocert"
)

// Route maps one public hostname to a TCP allocation exposed on the node.
// The upstream itself is plain HTTP; TLS terminates at Soar.
type Route struct {
	Domain       string
	UpstreamHost string
	UpstreamPort int
}

type compiledRoute struct {
	route Route
	proxy *httputil.ReverseProxy
}

// Manager owns the node-wide :80 listener used for HTTP routes and ACME
// challenges. HTTPS routes are dispatched by the existing Soar API listener
// on :443 so the daemon and user domains can safely share that port.
type Manager struct {
	mu           sync.RWMutex
	serverRoutes map[string][]Route
	routes       map[string]*compiledRoute
	httpServer   *http.Server
	certificates *autocert.Manager
}

var (
	defaultManager *Manager
	defaultOnce    sync.Once
)

func Configure(dataDir string) *Manager {
	defaultOnce.Do(func() {
		m := &Manager{
			serverRoutes: make(map[string][]Route),
			routes:       make(map[string]*compiledRoute),
		}
		m.certificates = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(dataDir, "http-routing", "certificates")),
			HostPolicy: m.hostPolicy,
		}
		installCertbotHooks()
		defaultManager = m
	})
	return defaultManager
}

func installCertbotHooks() {
	if runtime.GOOS != "linux" {
		return
	}
	root := "/etc/letsencrypt/renewal-hooks"
	if _, err := os.Stat("/etc/letsencrypt/renewal"); err != nil {
		return
	}
	hooks := map[string]string{
		filepath.Join(root, "pre", "stop-soar-http-routing"):   "#!/bin/sh\nsystemctl stop soar >/dev/null 2>&1 || true\n",
		filepath.Join(root, "post", "start-soar-http-routing"): "#!/bin/sh\nsystemctl start soar >/dev/null 2>&1 || true\n",
	}
	for filename, contents := range hooks {
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			log.WithField("subsystem", "http-routing").WithField("error", err).Warn("failed to prepare Certbot renewal hooks")
			return
		}
		if err := os.WriteFile(filename, []byte(contents), 0o755); err != nil {
			log.WithField("subsystem", "http-routing").WithField("error", err).Warn("failed to install Certbot renewal hook")
			return
		}
	}
}

func Default() *Manager { return defaultManager }

func normalizeDomain(value string) string {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return host
}

func (m *Manager) hostPolicy(_ context.Context, host string) error {
	m.mu.RLock()
	_, ok := m.routes[normalizeDomain(host)]
	m.mu.RUnlock()
	if !ok {
		return autocert.ErrCacheMiss
	}
	return nil
}

func newCompiledRoute(route Route) *compiledRoute {
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(route.UpstreamHost, itoa(route.UpstreamPort))}
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalHost := request.Host
		baseDirector(request)
		request.Host = originalHost
		request.Header.Set("X-Forwarded-Host", originalHost)
		if request.TLS == nil {
			request.Header.Set("X-Forwarded-Proto", "http")
		} else {
			request.Header.Set("X-Forwarded-Proto", "https")
		}
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, err error) {
		log.WithField("subsystem", "http-routing").WithField("domain", route.Domain).WithField("error", err).Warn("HTTP route upstream is unavailable")
		http.Error(writer, "Upstream service is unavailable", http.StatusBadGateway)
	}
	return &compiledRoute{route: route, proxy: proxy}
}

func (m *Manager) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	host := normalizeDomain(request.Host)
	m.mu.RLock()
	route := m.routes[host]
	m.mu.RUnlock()
	if route == nil {
		http.NotFound(writer, request)
		return
	}
	route.proxy.ServeHTTP(writer, request)
}

// Wrap dispatches configured user domains to their upstream while preserving
// the existing Soar API handler for the node's own hostname.
func (m *Manager) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := normalizeDomain(request.Host)
		m.mu.RLock()
		route := m.routes[host]
		m.mu.RUnlock()
		if route != nil {
			route.proxy.ServeHTTP(writer, request)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// GetCertificate lets autocert issue certificates only for configured user
// domains. Returning nil for any other SNI keeps the static Soar API
// certificate as the fallback certificate on the shared TLS listener.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m == nil {
		return nil, nil
	}
	host := normalizeDomain(hello.ServerName)
	m.mu.RLock()
	_, configured := m.routes[host]
	m.mu.RUnlock()
	if !configured {
		return nil, nil
	}
	return m.certificates.GetCertificate(hello)
}

func (m *Manager) HasRoute(host string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	_, configured := m.routes[normalizeDomain(host)]
	m.mu.RUnlock()
	return configured
}

// Reconcile replaces the routes contributed by a single server.
func (m *Manager) Reconcile(uuid string, routes []Route) {
	if m == nil {
		return
	}
	clean := make([]Route, 0, len(routes))
	for _, route := range routes {
		route.Domain = normalizeDomain(route.Domain)
		if route.Domain == "" || route.UpstreamHost == "" || route.UpstreamPort < 1 || route.UpstreamPort > 65535 {
			continue
		}
		clean = append(clean, route)
	}

	m.mu.Lock()
	if len(clean) == 0 {
		delete(m.serverRoutes, uuid)
	} else {
		m.serverRoutes[uuid] = clean
	}
	m.rebuildLocked()
	shouldRun := len(m.routes) > 0
	running := m.httpServer != nil
	if shouldRun && !running {
		m.startLocked()
	} else if !shouldRun && running {
		m.stopLocked()
	}
	m.mu.Unlock()
}

func (m *Manager) Remove(uuid string) { m.Reconcile(uuid, nil) }

func (m *Manager) rebuildLocked() {
	next := make(map[string]*compiledRoute)
	servers := make([]string, 0, len(m.serverRoutes))
	for uuid := range m.serverRoutes {
		servers = append(servers, uuid)
	}
	sort.Strings(servers)
	for _, uuid := range servers {
		for _, route := range m.serverRoutes[uuid] {
			if _, exists := next[route.Domain]; !exists {
				next[route.Domain] = newCompiledRoute(route)
			}
		}
	}
	m.routes = next
}

func (m *Manager) startLocked() {
	httpHandler := m.certificates.HTTPHandler(m)
	m.httpServer = &http.Server{Addr: ":80", Handler: httpHandler, ReadHeaderTimeout: 15 * time.Second}
	httpServer := m.httpServer
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithField("subsystem", "http-routing").WithField("error", err).Error("failed to listen on port 80")
		}
	}()
	log.WithField("subsystem", "http-routing").Info("started HTTP routing and certificate challenge listener")
}

func (m *Manager) stopLocked() {
	httpServer := m.httpServer
	m.httpServer = nil
	if httpServer != nil {
		_ = httpServer.Close()
	}
	log.WithField("subsystem", "http-routing").Info("stopped HTTP routing and certificate challenge listener")
}

func itoa(value int) string {
	// Avoid fmt in the hot path and keep the package dependency surface small.
	if value == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
