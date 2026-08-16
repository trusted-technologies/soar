package server

import (
	"net"
	"strings"

	"github.com/apex/log"
	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/l7"
)

// ReconcileL7 brings the L7 protection proxies for this server in line with
// its current configuration. One proxy runs per protected allocation port
// while the server is not suspended; ports removed from the configuration are
// stopped.
//
// Each proxy listens on the public allocation and forwards cleaned traffic to
// the container which, when protected, is bound to the Docker bridge interface
// instead of the public IP (see environment.Allocations.DockerBindings).
func (s *Server) ReconcileL7() {
	mgr := l7.Default()
	if mgr == nil {
		return
	}

	cfg := s.Config()
	alloc := cfg.Allocations

	var targets []l7.Target
	if alloc.L7Filter && !cfg.Suspended {
		if listenIP, ok := l7PublicIP(alloc.L7PublicHost, alloc.DefaultMapping.Ip); ok {
			iface := config.Get().Docker.Network.Interface
			for _, settings := range l7.ParseSettingsList(alloc.L7, alloc.DefaultMapping.Port) {
				targets = append(targets, l7.Target{
					UUID:        s.ID(),
					ListenIP:    listenIP,
					ListenPort:  settings.Port,
					BackendHost: iface,
					BackendPort: settings.Port,
					Settings:    settings,
				})
			}
		} else {
			s.Log().WithField("l7_public_host", alloc.L7PublicHost).Error("cannot start L7 proxy without a public node address")
		}
	}

	mgr.ReconcileServer(s.ID(), targets)
}

// l7PublicIP resolves the node's public host to a concrete local address. A
// wildcard listener would also occupy the Docker bridge port and prevent the
// protected container from starting.
func l7PublicIP(host, fallback string) (string, bool) {
	for _, candidate := range []string{strings.TrimSpace(host), strings.TrimSpace(fallback)} {
		if ip := net.ParseIP(candidate); ip != nil && !ip.IsUnspecified() {
			return ip.String(), true
		}
		if candidate == "" || candidate == "0.0.0.0" || candidate == "::" {
			continue
		}
		ips, err := net.LookupIP(candidate)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil && !ipv4.IsLoopback() && !ipv4.IsUnspecified() {
				return ipv4.String(), true
			}
		}
	}
	log.WithField("subsystem", "l7").WithField("host", host).Warn("could not resolve L7 public host")
	return "", false
}

// RemoveL7 stops and forgets any L7 proxy for this server. Called when a server
// is deleted from the node.
func (s *Server) RemoveL7() {
	if mgr := l7.Default(); mgr != nil {
		mgr.Remove(s.ID())
	}
}
