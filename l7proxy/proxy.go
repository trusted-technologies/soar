package l7proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/apex/log"
)

// Config holds the L7 proxy configuration.
type Config struct {
	// ListenAddr is the address the L7 proxy listens on (e.g., "0.0.0.0:25565").
	ListenAddr string
	// BackendAddr is the address of the game server (e.g., "127.0.0.1:25566").
	BackendAddr string
	// RateLimitPerSec limits connections per IP per second.
	RateLimitPerSec int
	// MaxConcurrentConnections is the max number of simultaneous connections.
	MaxConcurrentConnections int
}

// Proxy is the L7 DDoS protection proxy for Minecraft servers.
type Proxy struct {
	config Config
	log    *log.Entry

	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc

	// Rate limiting
	rateLimitMu sync.Mutex
	rateLimits  map[string]*RateLimiter

	// Connection tracking
	connMu          sync.Mutex
	activeConnCount int
}

// RateLimiter tracks per-IP connection rates.
type RateLimiter struct {
	lastReset time.Time
	count     int
	limit     int
}

// New creates a new L7 proxy instance.
func New(config Config, logger *log.Entry) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{
		config:     config,
		log:        logger,
		ctx:        ctx,
		cancel:     cancel,
		rateLimits: make(map[string]*RateLimiter),
	}
}

// Start starts listening for incoming connections.
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("l7proxy: listen failed: %w", err)
	}
	p.listener = listener
	p.log.WithField("addr", p.config.ListenAddr).Info("L7 proxy listening")

	go p.acceptLoop()
	return nil
}

// Stop gracefully shuts down the proxy.
func (p *Proxy) Stop() error {
	p.cancel()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// acceptLoop accepts incoming connections and routes them.
func (p *Proxy) acceptLoop() {
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				p.log.WithError(err).Warn("accept error")
			}
			continue
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single client connection.
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientIP := clientConn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Rate limiting check
	if !p.checkRateLimit(clientIP) {
		p.log.WithField("ip", clientIP).Debug("rate limit exceeded")
		clientConn.Close()
		return
	}

	// Connection limit check
	p.connMu.Lock()
	if p.activeConnCount >= p.config.MaxConcurrentConnections {
		p.connMu.Unlock()
		p.log.WithField("ip", clientIP).Debug("max connections reached")
		clientConn.Close()
		return
	}
	p.activeConnCount++
	p.connMu.Unlock()

	defer func() {
		p.connMu.Lock()
		p.activeConnCount--
		p.connMu.Unlock()
	}()

	// Read Minecraft handshake
	hs, handshakeRaw, err := ReadHandshake(clientConn)
	if err != nil {
		p.log.WithField("ip", clientIP).WithError(err).Debug("failed to read handshake")
		return
	}

	p.log.WithFields(log.Fields{
		"ip":     clientIP,
		"server": hs.ServerAddress,
		"port":   hs.ServerPort,
		"state":  hs.NextState,
		"proto":  hs.ProtocolVersion,
	}).Debug("handshake received")

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", p.config.BackendAddr, 5*time.Second)
	if err != nil {
		p.log.WithField("backend", p.config.BackendAddr).WithError(err).Warn("backend connection failed")
		return
	}
	defer backendConn.Close()

	// Send handshake to backend
	if _, err := backendConn.Write(handshakeRaw); err != nil {
		p.log.WithError(err).Warn("failed to send handshake to backend")
		return
	}

	// Bidirectional proxy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = copyBuffer(backendConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = copyBuffer(clientConn, backendConn)
	}()

	wg.Wait()
}

// copyBuffer is a buffered io.Copy replacement.
func copyBuffer(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
		}
		if err != nil {
			return written, err
		}
	}
}

// checkRateLimit checks if an IP has exceeded its rate limit.
func (p *Proxy) checkRateLimit(ip string) bool {
	p.rateLimitMu.Lock()
	defer p.rateLimitMu.Unlock()

	now := time.Now()
	limiter, exists := p.rateLimits[ip]

	if !exists {
		limiter = &RateLimiter{
			lastReset: now,
			count:     1,
			limit:     p.config.RateLimitPerSec,
		}
		p.rateLimits[ip] = limiter
		return true
	}

	// Reset if a second has passed
	if now.Sub(limiter.lastReset) >= time.Second {
		limiter.lastReset = now
		limiter.count = 1
		return true
	}

	// Check if under limit
	if limiter.count < limiter.limit {
		limiter.count++
		return true
	}

	return false
}
