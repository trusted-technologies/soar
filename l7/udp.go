package l7

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/apex/log"
)

// establishGrace is how long a UDP flow must stay alive with bidirectional
// traffic before its address counts as verified. Verified addresses keep
// connecting during mitigation; fresh addresses are dropped while an attack
// is in progress.
const establishGrace = 10 * time.Second

// rateCounter is a tiny fixed-window packets-per-second counter.
type rateCounter struct {
	mu    sync.Mutex
	sec   int64
	count int
}

func (r *rateCounter) allow(limit int) bool {
	if limit <= 0 {
		return true
	}
	now := time.Now().Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sec != now {
		r.sec = now
		r.count = 0
	}
	r.count++
	return r.count <= limit
}

// udpFlow is one client address talking to the backend through the proxy.
type udpFlow struct {
	client   *net.UDPAddr
	up       *net.UDPConn
	ip       string
	pps      rateCounter
	mu       sync.Mutex
	lastSeen time.Time
	started  time.Time
	replied  bool
	trusted  bool
}

func (f *udpFlow) touch() {
	f.mu.Lock()
	f.lastSeen = time.Now()
	f.mu.Unlock()
}

// udpProxy is the generic UDP protection engine: a NAT-style forwarder with
// per-IP rate limits, session caps, firewall rules and attack mitigation.
type udpProxy struct {
	uuid   string
	listen string

	mu       sync.RWMutex
	settings Settings
	rules    *compiledRules
	backend  backend

	tracker *tracker
	stats   *stats
	lists   *listService

	ln       *net.UDPConn
	listenIP *net.UDPAddr
	flows    map[string]*udpFlow
	flowMu   sync.Mutex

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newUDPProxy(uuid, listen string, be backend, s Settings, lists *listService) *udpProxy {
	return &udpProxy{
		uuid:     uuid,
		listen:   listen,
		settings: s,
		rules:    compileRules(s),
		backend:  be,
		tracker:  newTracker(),
		stats:    newStats(),
		lists:    lists,
		flows:    make(map[string]*udpFlow),
	}
}

func (p *udpProxy) listenAddr() string { return p.listen }

// presetName reports the configured preset (udp/geyser/bedrock) so the manager
// restarts the listener when the preset changes and stats report it correctly.
func (p *udpProxy) presetName() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if isUDPPreset(p.settings.Preset) {
		return p.settings.Preset
	}
	return PresetUDP
}

func (p *udpProxy) start() error {
	addr, err := net.ResolveUDPAddr("udp", p.listen)
	if err != nil {
		return err
	}
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.ln = ln
	p.listenIP = addr
	p.cancel = cancel
	p.rules.require(p.lists)

	p.wg.Add(1)
	go p.readLoop(ctx)
	p.wg.Add(1)
	go p.gcLoop(ctx)
	log.WithField("subsystem", "l7").WithField("server", p.uuid).WithField("listen", p.listen).Info("started L7 UDP proxy")
	return nil
}

func (p *udpProxy) stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.ln != nil {
		_ = p.ln.Close()
	}
	p.flowMu.Lock()
	for key, f := range p.flows {
		_ = f.up.Close()
		delete(p.flows, key)
	}
	p.flowMu.Unlock()
	p.wg.Wait()
	log.WithField("subsystem", "l7").WithField("server", p.uuid).Info("stopped L7 UDP proxy")
}

func (p *udpProxy) update(s Settings, be backend) {
	p.mu.Lock()
	p.settings = s
	p.rules = compileRules(s)
	p.backend = be
	p.mu.Unlock()
	p.rules.require(p.lists)
}

func (p *udpProxy) getSettings() (Settings, *compiledRules, backend) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.settings, p.rules, p.backend
}

func (p *udpProxy) verify(ip string) {
	s, _, _ := p.getSettings()
	p.tracker.allow(ip, s.AllowSeconds)
}

func (p *udpProxy) snapshot() StatsSnapshot {
	s, _, _ := p.getSettings()
	out := p.stats.snapshot()
	cps, mitigation, verified, banned, tracked := p.tracker.snapshot(s)
	out.Enabled = true
	out.Port = s.Port
	out.Preset = p.presetName()
	out.Mode = s.Mode
	out.Mitigation = mitigation
	out.CPS = cps
	out.VerifiedIPs = verified
	out.BannedIPs = banned
	out.TrackedIPs = tracked
	return out
}

func (p *udpProxy) readLoop(ctx context.Context) {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := p.ln.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				var ne net.Error
				if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary()) {
					continue
				}
				return
			}
		}
		if n == 0 {
			continue
		}
		p.handlePacket(ctx, buf[:n], addr)
	}
}

func (p *udpProxy) handlePacket(ctx context.Context, data []byte, addr *net.UDPAddr) {
	key := addr.String()

	p.flowMu.Lock()
	flow, ok := p.flows[key]
	p.flowMu.Unlock()

	s, rules, be := p.getSettings()

	if ok {
		if !flow.trusted && !flow.pps.allow(s.UDPMaxPPS) {
			p.stats.block(reasonRateLimit)
			return
		}
		flow.touch()
		if _, err := flow.up.Write(data); err != nil {
			p.dropFlow(key)
		}
		return
	}

	// New flow: run the firewall and rate gates before allocating anything.
	ip := addr.IP.String()
	netIP := addr.IP
	p.stats.total.Add(1)

	trusted := !rules.whitelist.empty() && rules.whitelist.contains(netIP)
	if !trusted {
		if p.tracker.isBanned(ip) {
			p.stats.block(reasonBanned)
			return
		}
		if rules.blacklist.contains(netIP) {
			p.stats.block(reasonFirewall)
			return
		}
		if rules.needsGeo {
			if c := p.lists.countryOf(netIP); c != "" {
				if _, blocked := rules.countries[c]; blocked {
					p.stats.block(reasonCountry)
					return
				}
			}
		}
		if rules.needsASN {
			if a := p.lists.asnOf(netIP); a != 0 {
				if _, blocked := rules.asns[a]; blocked {
					p.stats.block(reasonASN)
					return
				}
			}
		}
		if rules.needsVPN && p.lists.isVPN(netIP) {
			p.stats.block(reasonVPN)
			return
		}
	}

	_, mitigation := p.tracker.hit(s)
	if mitigation && !trusted && !p.tracker.isVerified(ip) {
		// During an attack only addresses with an established history pass.
		p.stats.block(reasonMitigation)
		return
	}

	if !trusted && !p.tracker.openSession(ip, s.MaxSessionsPerIP) {
		p.tracker.closeSession(ip)
		p.stats.block(reasonSessionLimit)
		return
	}

	up, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(be.host), Port: be.port})
	if err != nil {
		if !trusted {
			p.tracker.closeSession(ip)
		}
		p.stats.block(reasonBackendDown)
		return
	}

	flow = &udpFlow{client: addr, up: up, ip: ip, lastSeen: time.Now(), started: time.Now(), trusted: trusted}
	p.flowMu.Lock()
	p.flows[key] = flow
	p.flowMu.Unlock()
	p.stats.passed.Add(1)

	p.wg.Add(1)
	go p.replyLoop(ctx, key, flow)

	// PROXY protocol v2 for UDP: send the header as its own first datagram of
	// the logical flow so the upstream (e.g. GeyserMC with
	// use-haproxy-protocol) can recover the player's real IP and port.
	// Subsequent datagrams carry the raw RakNet payload unchanged. Never
	// emitted for the bedrock preset (ApplyDefaults forces ProxyProtocol off).
	if s.ProxyProtocol {
		if hdr := proxyProtocolV2HeaderUDP(addr, p.listenIP); hdr != nil {
			if _, err := up.Write(hdr); err != nil {
				p.dropFlow(key)
				return
			}
		}
	}

	if _, err := up.Write(data); err != nil {
		p.dropFlow(key)
	}
}

// replyLoop copies backend responses back to the client through the shared
// public listener so the source address matches what the client expects.
func (p *udpProxy) replyLoop(ctx context.Context, key string, flow *udpFlow) {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	for {
		s, _, _ := p.getSettings()
		_ = flow.up.SetReadDeadline(time.Now().Add(time.Duration(s.UDPSessionTimeoutSeconds) * time.Second))
		n, err := flow.up.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
			default:
			}
			p.dropFlow(key)
			return
		}
		if n == 0 {
			continue
		}
		flow.mu.Lock()
		flow.lastSeen = time.Now()
		flow.replied = true
		flow.mu.Unlock()
		if _, err := p.ln.WriteToUDP(buf[:n], flow.client); err != nil {
			p.dropFlow(key)
			return
		}
	}
}

func (p *udpProxy) dropFlow(key string) {
	p.flowMu.Lock()
	flow, ok := p.flows[key]
	if ok {
		delete(p.flows, key)
	}
	p.flowMu.Unlock()
	if ok {
		_ = flow.up.Close()
		if !flow.trusted {
			p.tracker.closeSession(flow.ip)
		}
	}
}

// gcLoop expires idle flows, promotes established flows to verified addresses
// and prunes the tracker.
func (p *udpProxy) gcLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	pruneEvery := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s, _, _ := p.getSettings()
		timeout := time.Duration(s.UDPSessionTimeoutSeconds) * time.Second
		now := time.Now()

		p.flowMu.Lock()
		expired := make([]string, 0)
		promote := make([]string, 0)
		for key, f := range p.flows {
			f.mu.Lock()
			idle := now.Sub(f.lastSeen)
			established := f.replied && now.Sub(f.started) >= establishGrace
			f.mu.Unlock()
			if idle > timeout {
				expired = append(expired, key)
				continue
			}
			if established && !f.trusted {
				promote = append(promote, f.ip)
			}
		}
		p.flowMu.Unlock()

		for _, key := range expired {
			p.dropFlow(key)
		}
		for _, ip := range promote {
			if !p.tracker.isVerified(ip) {
				p.tracker.allow(ip, s.AllowSeconds)
			}
		}

		pruneEvery++
		if pruneEvery >= 12 {
			pruneEvery = 0
			p.tracker.prune()
		}
	}
}
