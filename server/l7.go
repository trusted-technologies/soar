package server

import (
	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/l7"
)

// ReconcileL7 brings the L7 protection proxy for this server in line with its
// current configuration. A proxy is run whenever the default allocation has L7
// filtering enabled and the server is not suspended; otherwise any running
// proxy is stopped.
//
// The proxy listens on the public default allocation and forwards cleaned
// traffic to the container which, when protected, is bound to the Docker bridge
// interface instead of the public IP (see environment.Allocations.DockerBindings).
func (s *Server) ReconcileL7() {
	mgr := l7.Default()
	if mgr == nil {
		return
	}

	cfg := s.Config()
	alloc := cfg.Allocations
	enabled := alloc.L7Filter && !cfg.Suspended

	if !enabled {
		mgr.Reconcile(s.ID(), false, l7.Target{UUID: s.ID()})
		return
	}

	mgr.Reconcile(s.ID(), true, l7.Target{
		UUID:        s.ID(),
		ListenIP:    alloc.DefaultMapping.Ip,
		ListenPort:  alloc.DefaultMapping.Port,
		BackendHost: config.Get().Docker.Network.Interface,
		BackendPort: alloc.DefaultMapping.Port,
		Settings:    l7.ParseSettings(alloc.L7),
	})
}

// RemoveL7 stops and forgets any L7 proxy for this server. Called when a server
// is deleted from the node.
func (s *Server) RemoveL7() {
	if mgr := l7.Default(); mgr != nil {
		mgr.Remove(s.ID())
	}
}
