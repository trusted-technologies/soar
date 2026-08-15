package server

import (
	"fmt"

	"github.com/apex/log"
	"github.com/pterodactyl/wings/l7proxy"
)

// StartL7Proxy starts the L7 proxy if L7Filter is enabled for this server.
func (s *Server) StartL7Proxy() error {
	s.l7Lock.Lock()
	defer s.l7Lock.Unlock()

	// Check if L7Filter is enabled
	cfg := s.Config()
	if !cfg.Allocations.L7Filter {
		return nil
	}

	// Already running
	if s.l7proxy != nil {
		return nil
	}

	// Get the primary allocation
	primaryIP := cfg.Allocations.DefaultMapping.Ip
	primaryPort := cfg.Allocations.DefaultMapping.Port

	// Calculate backend port (where Docker container is bound)
	backendPort := primaryPort + 20000
	if backendPort > 65535 {
		backendPort = primaryPort + 10000
	}

	listenAddr := fmt.Sprintf("%s:%d", primaryIP, primaryPort)
	backendAddr := fmt.Sprintf("127.0.0.1:%d", backendPort)

	proxyConfig := l7proxy.Config{
		ListenAddr:               listenAddr,
		BackendAddr:              backendAddr,
		RateLimitPerSec:          10,
		MaxConcurrentConnections: 500,
	}

	s.l7proxy = l7proxy.New(proxyConfig, s.Log().WithField("subsystem", "l7proxy"))

	if err := s.l7proxy.Start(); err != nil {
		s.l7proxy = nil
		return fmt.Errorf("failed to start L7 proxy: %w", err)
	}

	s.Log().WithFields(log.Fields{
		"listen":  listenAddr,
		"backend": backendAddr,
	}).Info("L7 DDoS protection enabled")

	return nil
}

// StopL7Proxy stops the L7 proxy if it's running.
func (s *Server) StopL7Proxy() error {
	s.l7Lock.Lock()
	defer s.l7Lock.Unlock()

	if s.l7proxy == nil {
		return nil
	}

	s.Log().Info("stopping L7 proxy")
	err := s.l7proxy.Stop()
	s.l7proxy = nil

	return err
}
