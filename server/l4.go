package server

import (
	"github.com/pterodactyl/wings/l4"
)

// ReconcileL4 brings the L4 (iptables) firewall rules for this server in line
// with its current configuration. Rules are installed per protected allocation
// port and, unlike L7, run regardless of power state so an idle server's ports
// stay protected. Ports removed from the configuration have their rules torn
// down.
func (s *Server) ReconcileL4() {
	mgr := l4.Default()
	if mgr == nil {
		return
	}

	cfg := s.Config()
	alloc := cfg.Allocations

	var targets []l4.Target
	if alloc.L4Filter {
		if ip, ok := l7PublicIP(alloc.L7PublicHost, alloc.DefaultMapping.Ip); ok {
			for _, settings := range l4.ParseSettingsList(alloc.L4, alloc.DefaultMapping.Port) {
				targets = append(targets, l4.Target{
					IP:       ip,
					Port:     settings.Port,
					Settings: settings,
				})
			}
		} else {
			s.Log().WithField("l7_public_host", alloc.L7PublicHost).Error("cannot install L4 rules without a public node address")
		}
	}

	mgr.ReconcileServer(s.ID(), targets)
}

// RemoveL4 tears down any L4 firewall rules for this server. Called when a
// server is deleted from the node.
func (s *Server) RemoveL4() {
	if mgr := l4.Default(); mgr != nil {
		mgr.Remove(s.ID())
	}
}
