package l7

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/apex/log"
)

// Timeouts applied to the pre-play handshake so that slowloris style
// connections cannot tie up resources.
const (
	handshakeReadTimeout = 5 * time.Second
	backendDialTimeout   = 5 * time.Second
	statusCacheGrace     = time.Second
)

// backend describes where cleaned traffic should be forwarded.
type backend struct {
	host string
	port int
}

func (b backend) addr() string { return net.JoinHostPort(b.host, strconv.Itoa(b.port)) }

// cachedStatus is a status (ping) response cached to answer floods without
// touching the backend.
type cachedStatus struct {
	mu       sync.Mutex
	json     []byte
	fetched  time.Time
	protocol int32
}

// proxy is a single Minecraft-aware TCP filter listening on one public
// allocation and forwarding validated traffic to a container backend.
type proxy struct {
	uuid    string
	nodeID  string
	listen  string
	backend backend

	mu       sync.RWMutex
	settings Settings
	rules    *compiledRules
	backOK   bool

	tracker  *tracker
	stats    *stats
	status   cachedStatus
	lists    *listService
	captcha  *captchaStore
	baseURL  string

	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newProxy(uuid, nodeID, listen string, be backend, s Settings, lists *listService, captcha *captchaStore, baseURL string) *proxy {
	return &proxy{
		uuid:     uuid,
		nodeID:   nodeID,
		listen:   listen,
		backend:  be,
		settings: s,
		rules:    compileRules(s),
		tracker:  newTracker(),
		stats:    newStats(),
		lists:    lists,
		captcha:  captcha,
		baseURL:  baseURL,
	}
}

func (p *proxy) start() error {
	ln, err := net.Listen("tcp", p.listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.ln = ln
	p.cancel = cancel
	p.rules.require(p.lists)

	p.wg.Add(1)
	go p.acceptLoop(ctx)
	p.wg.Add(1)
	go p.pruneLoop(ctx)
	log.WithField("subsystem", "l7").WithField("server", p.uuid).WithField("listen", p.listen).Info("started L7 proxy")
	return nil
}

func (p *proxy) stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.ln != nil {
		_ = p.ln.Close()
	}
	p.wg.Wait()
	log.WithField("subsystem", "l7").WithField("server", p.uuid).Info("stopped L7 proxy")
}

func (p *proxy) update(s Settings, be backend) {
	p.mu.Lock()
	p.settings = s
	p.rules = compileRules(s)
	p.backend = be
	p.mu.Unlock()
	p.rules.require(p.lists)
}

func (p *proxy) getSettings() (Settings, *compiledRules, backend) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.settings, p.rules, p.backend
}

func (p *proxy) setBackendHealthy(ok bool) {
	p.mu.Lock()
	p.backOK = ok
	p.mu.Unlock()
}

func (p *proxy) pruneLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.tracker.prune()
		}
	}
}

func (p *proxy) acceptLoop(ctx context.Context) {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				return
			}
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(ctx, conn)
		}()
	}
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

func (p *proxy) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	s, rules, be := p.getSettings()
	p.stats.total.Add(1)

	ip := remoteIP(conn)
	netIP := net.ParseIP(ip)

	cps, mitigation := p.tracker.hit(s)
	_ = cps

	// Static allow/deny lists are the very first gate.
	if !rules.whitelist.empty() && rules.whitelist.contains(netIP) {
		p.forwardAll(ctx, conn, be, s, mitigation)
		return
	}
	if p.tracker.isBanned(ip) {
		p.stats.block(reasonBanned)
		p.rejectLogin(conn, s.MitigationMessage)
		return
	}
	if rules.blacklist.contains(netIP) {
		p.stats.block(reasonFirewall)
		p.rejectLogin(conn, s.FirewallMessage)
		return
	}

	// Read the handshake to learn the client's intent before deciding.
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	br := bufio.NewReader(conn)
	hsPayload, hsRaw, err := readFrame(br, maxHandshakeFrame)
	if err != nil {
		if errors.Is(err, errLegacyPing) {
			p.stats.block(reasonLegacyPing)
		} else {
			p.stats.block(reasonProtocol)
			p.tracker.ban(ip, s.BanSeconds)
		}
		return
	}
	hs, err := parseHandshake(hsPayload)
	if err != nil {
		p.stats.block(reasonProtocol)
		p.tracker.ban(ip, s.BanSeconds)
		return
	}

	if hs.nextState == stateStatus {
		p.handleStatus(ctx, conn, br, hsRaw, hs, s, be)
		return
	}

	p.handleLogin(ctx, conn, br, hsRaw, hs, s, rules, be, mitigation, ip, netIP)
}

// handleStatus answers server list pings, serving from cache during floods.
func (p *proxy) handleStatus(ctx context.Context, conn net.Conn, br *bufio.Reader, hsRaw []byte, hs handshake, s Settings, be backend) {
	p.stats.pings.Add(1)
	ip := remoteIP(conn)
	if !p.tracker.statusAllowed(ip) {
		p.stats.block(reasonStatusFlood)
		return
	}

	// Read the status request packet (empty payload, id 0x00).
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	reqPayload, _, err := readFrame(br, maxStatusFrame)
	if err != nil || len(reqPayload) == 0 || reqPayload[0] != 0x00 {
		return
	}

	statusJSON, ok := p.statusResponse(ctx, hsRaw, hs, s, be)
	if !ok {
		statusJSON = offlineStatusJSON(s.OfflineMOTD, hs.protocol)
	} else {
		statusJSON = adjustStatusJSON(statusJSON, s.FakeOnline)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(handshakeReadTimeout))
	if err := writeStatusResponse(conn, statusJSON); err != nil {
		return
	}
	// Answer the ping/pong so the client shows a latency value.
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	if payload, _, err := readFrame(br, maxStatusFrame); err == nil && len(payload) > 0 && payload[0] == 0x01 {
		_ = conn.SetWriteDeadline(time.Now().Add(handshakeReadTimeout))
		_ = writePacket(conn, 0x01, payload[1:])
	}
}

// statusResponse returns a cached status document or fetches a fresh one from
// the backend. The boolean is false when the backend is unreachable.
func (p *proxy) statusResponse(ctx context.Context, hsRaw []byte, hs handshake, s Settings, be backend) ([]byte, bool) {
	p.status.mu.Lock()
	if p.status.json != nil && time.Since(p.status.fetched) < time.Duration(s.MOTDCacheSeconds)*time.Second {
		cached := p.status.json
		p.status.mu.Unlock()
		return cached, true
	}
	p.status.mu.Unlock()

	statusJSON, err := p.fetchBackendStatus(ctx, hsRaw, hs, be)
	if err != nil {
		p.setBackendHealthy(false)
		// Serve a slightly stale cache during brief backend hiccups.
		p.status.mu.Lock()
		if p.status.json != nil && time.Since(p.status.fetched) < time.Duration(s.MOTDCacheSeconds)*time.Second+statusCacheGrace {
			cached := p.status.json
			p.status.mu.Unlock()
			return cached, true
		}
		p.status.mu.Unlock()
		return nil, false
	}
	p.setBackendHealthy(true)
	p.status.mu.Lock()
	p.status.json = statusJSON
	p.status.fetched = time.Now()
	p.status.protocol = hs.protocol
	p.status.mu.Unlock()
	return statusJSON, true
}

// fetchBackendStatus performs a status handshake against the backend and
// returns the raw status JSON.
func (p *proxy) fetchBackendStatus(ctx context.Context, hsRaw []byte, hs handshake, be backend) ([]byte, error) {
	d := net.Dialer{Timeout: backendDialTimeout}
	up, err := d.DialContext(ctx, "tcp", be.addr())
	if err != nil {
		return nil, err
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(backendDialTimeout))

	// Rebuild a clean status handshake toward the backend using the real
	// backend host/port so vhost-aware servers respond correctly.
	rebuilt := buildHandshake(hs.protocol, be.host, uint16(be.port), stateStatus)
	if _, err := up.Write(rebuilt); err != nil {
		return nil, err
	}
	if err := writePacket(up, 0x00, nil); err != nil {
		return nil, err
	}
	rb := bufio.NewReader(up)
	payload, _, err := readFrame(rb, maxStatusResponse)
	if err != nil {
		return nil, err
	}
	// Payload is packet id (0x00) + string status JSON.
	if len(payload) < 1 || payload[0] != 0x00 {
		return nil, errMalformedFrame
	}
	return extractStatusJSON(payload[1:])
}

func (p *proxy) handleLogin(ctx context.Context, conn net.Conn, br *bufio.Reader, hsRaw []byte, hs handshake, s Settings, rules *compiledRules, be backend, mitigation bool, ip string, netIP net.IP) {
	// A reconnect within the verify window after a challenge marks the address
	// as verified. This is the cheap first line of defense: fire-and-forget
	// flood bots never reconnect, real players do.
	if !p.tracker.isVerified(ip) {
		p.tracker.completeChallenge(ip, s.AllowSeconds)
	}
	verified := p.tracker.isVerified(ip)

	// Firewall: country / ASN / VPN checks (skipped for verified addresses).
	if !verified && netIP != nil {
		if rules.needsGeo {
			if c := p.lists.countryOf(netIP); c != "" {
				if _, blocked := rules.countries[c]; blocked {
					p.stats.block(reasonCountry)
					p.rejectLogin(conn, s.FirewallMessage)
					return
				}
			}
		}
		if rules.needsASN {
			if a := p.lists.asnOf(netIP); a != 0 {
				if _, blocked := rules.asns[a]; blocked {
					p.stats.block(reasonASN)
					p.rejectLogin(conn, s.FirewallMessage)
					return
				}
			}
		}
		if rules.needsVPN && p.lists.isVPN(netIP) {
			if s.VPNAction == "captcha" && s.CaptchaEnabled {
				p.issueCaptcha(conn, ip, s)
				p.stats.block(reasonVPN)
				return
			}
			p.stats.block(reasonVPN)
			p.rejectLogin(conn, s.VPNMessage)
			return
		}
	}

	// Rate limits and session accounting.
	if !verified {
		if p.tracker.inReconnectCooldown(ip, s.ReconnectCooldownSeconds) {
			p.stats.block(reasonReconnectCooldown)
			p.rejectLogin(conn, s.MitigationMessage)
			return
		}
		if !p.tracker.loginAllowed(ip, s.MaxLoginsPerSecond) {
			p.stats.block(reasonLoginRate)
			p.tracker.ban(ip, s.BanSeconds)
			p.rejectLogin(conn, s.MitigationMessage)
			return
		}
	}
	if !p.tracker.openSession(ip, s.MaxSessionsPerIP) {
		p.tracker.closeSession(ip)
		p.stats.block(reasonSessionLimit)
		p.rejectLogin(conn, s.MitigationMessage)
		return
	}
	defer p.tracker.closeSession(ip)

	// Read the login start to inspect the username and client type.
	_ = conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	loginPayload, loginRaw, err := readFrame(br, maxLoginFrame)
	if err != nil {
		p.stats.block(reasonProtocol)
		p.tracker.ban(ip, s.BanSeconds)
		return
	}
	name, err := parseLoginStart(loginPayload)
	if err != nil {
		p.stats.block(reasonProtocol)
		p.tracker.ban(ip, s.BanSeconds)
		return
	}

	if !clientTypeAllowed(s.ClientFilter, hs.clientType()) {
		p.stats.block(reasonClientType)
		p.rejectLogin(conn, s.FirewallMessage)
		return
	}
	if !nicknameAllowed(s, rules, name) {
		p.stats.block(reasonNickname)
		p.rejectLogin(conn, s.FirewallMessage)
		return
	}

	// Bot detection ladder.
	if !verified {
		statusSeen := p.tracker.hasStatusSeen(ip)
		strikes := p.tracker.currentStrikes(ip)
		switch gate(s, mitigation, statusSeen, strikes) {
		case gateChallengeReconnect:
			p.tracker.challenge(ip)
			p.stats.block(reasonChallenge)
			p.rejectLogin(conn, "§ePlease reconnect to verify your connection.")
			return
		case gateChallengeCaptcha:
			p.issueCaptcha(conn, ip, s)
			p.stats.block(reasonCaptcha)
			return
		}
	}

	// Backend health check before we commit the player.
	if !p.backendHealthy() {
		if !p.probeBackend(ctx, be) {
			p.stats.block(reasonBackendDown)
			p.rejectLogin(conn, s.OfflineKickMessage)
			return
		}
	}

	p.stats.passed.Add(1)
	p.forwardLogin(ctx, conn, br, be, s, hs, netIP, [][]byte{hsRaw, loginRaw})
}

func (p *proxy) backendHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.backOK
}

func (p *proxy) probeBackend(ctx context.Context, be backend) bool {
	d := net.Dialer{Timeout: backendDialTimeout}
	c, err := d.DialContext(ctx, "tcp", be.addr())
	if err != nil {
		p.setBackendHealthy(false)
		return false
	}
	_ = c.Close()
	p.setBackendHealthy(true)
	return true
}

// forwardLogin opens the backend connection, replays the buffered frames and
// pipes the two streams until either side closes.
func (p *proxy) forwardLogin(ctx context.Context, conn net.Conn, br *bufio.Reader, be backend, s Settings, hs handshake, netIP net.IP, replay [][]byte) {
	d := net.Dialer{Timeout: backendDialTimeout}
	up, err := d.DialContext(ctx, "tcp", be.addr())
	if err != nil {
		p.setBackendHealthy(false)
		p.rejectLogin(conn, s.OfflineKickMessage)
		return
	}
	defer up.Close()

	if s.ProxyProtocol {
		if hdr := proxyProtocolV2Header(conn.RemoteAddr(), conn.LocalAddr()); hdr != nil {
			if _, err := up.Write(hdr); err != nil {
				return
			}
		}
	}
	for _, frame := range replay {
		if _, err := up.Write(frame); err != nil {
			return
		}
	}

	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})
	pipe(conn, br, up)
}

// forwardAll transparently forwards a whitelisted connection without inspecting
// the Minecraft protocol at all.
func (p *proxy) forwardAll(ctx context.Context, conn net.Conn, be backend, s Settings, mitigation bool) {
	_ = mitigation
	d := net.Dialer{Timeout: backendDialTimeout}
	up, err := d.DialContext(ctx, "tcp", be.addr())
	if err != nil {
		p.setBackendHealthy(false)
		return
	}
	defer up.Close()
	if s.ProxyProtocol {
		if hdr := proxyProtocolV2Header(conn.RemoteAddr(), conn.LocalAddr()); hdr != nil {
			_, _ = up.Write(hdr)
		}
	}
	p.stats.passed.Add(1)
	pipe(conn, bufio.NewReader(conn), up)
}

func (p *proxy) rejectLogin(conn net.Conn, message string) {
	_ = conn.SetWriteDeadline(time.Now().Add(handshakeReadTimeout))
	_ = writeLoginDisconnect(conn, message)
}

func (p *proxy) issueCaptcha(conn net.Conn, ip string, s Settings) {
	code := p.captcha.issue(p.nodeID, p.uuid, ip)
	link := p.baseURL + "/captcha?c=" + code
	msg := "§eVerification required!\n§7Open this link in your browser:\n§b" + link + "\n§7Then reconnect to the server."
	p.rejectLogin(conn, msg)
}

// snapshot returns the current statistics for this proxy.
func (p *proxy) snapshot() StatsSnapshot {
	s, _, _ := p.getSettings()
	out := p.stats.snapshot()
	cps, mitigation, verified, banned, tracked := p.tracker.snapshot(s)
	out.Enabled = true
	out.Mode = s.Mode
	out.Mitigation = mitigation
	out.CPS = cps
	out.VerifiedIPs = verified
	out.BannedIPs = banned
	out.TrackedIPs = tracked
	return out
}

// verify marks an address as verified after a captcha was solved.
func (p *proxy) verify(ip string) {
	s, _, _ := p.getSettings()
	p.tracker.allow(ip, s.AllowSeconds)
}

func clientTypeAllowed(f ClientFilter, clientType string) bool {
	switch clientType {
	case "forge":
		return f.Forge
	default:
		// Vanilla and Fabric are indistinguishable during the handshake.
		return f.Vanilla || f.Fabric
	}
}

func nicknameAllowed(s Settings, rules *compiledRules, name string) bool {
	n := len([]rune(name))
	if n < s.NicknameMinLength || n > s.NicknameMaxLength {
		return false
	}
	if rules.nickWhitelist != nil && !rules.nickWhitelist.MatchString(name) {
		return false
	}
	if rules.nickBlacklist != nil && rules.nickBlacklist.MatchString(name) {
		return false
	}
	return true
}

// pipe copies bidirectionally between the client (via its buffered reader) and
// the backend, closing both when either direction ends.
func pipe(client net.Conn, clientReader io.Reader, backend net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(backend, clientReader)
		if c, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, backend)
		if c, ok := client.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

// require binds a compiled rule set to the shared list service so the required
// databases start downloading.
func (r *compiledRules) require(l *listService) {
	if r == nil || l == nil {
		return
	}
	l.require(r.needsGeo, r.needsASN, r.needsVPN)
}
