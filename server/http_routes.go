package server

import (
	"net"
	"strings"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/httpgateway"
)

// ReconcileHTTPRoutes contributes this server's hostname routes to the shared
// node gateway. The gateway owns port 80 and shares Soar's API listener on 443.
func (s *Server) ReconcileHTTPRoutes() {
	mgr := httpgateway.Default()
	if mgr == nil {
		return
	}
	cfg := s.Config()
	if cfg.Suspended {
		mgr.Remove(s.ID())
		return
	}
	routes := make([]httpgateway.Route, 0, len(cfg.Allocations.HTTPRoutes))
	for _, route := range cfg.Allocations.HTTPRoutes {
		host := strings.TrimSpace(route.UpstreamHost)
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		} else if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			host = config.Get().Docker.Network.Interface
		}
		// L7 moves the primary allocation off the public bind and onto the
		// Docker bridge. Route directly to that bridge listener as well.
		if cfg.Allocations.L7Filter && route.UpstreamPort == cfg.Allocations.DefaultMapping.Port {
			host = config.Get().Docker.Network.Interface
		}
		routes = append(routes, httpgateway.Route{
			Domain:       route.Domain,
			UpstreamHost: host,
			UpstreamPort: route.UpstreamPort,
		})
	}
	mgr.Reconcile(s.ID(), routes)
}

func (s *Server) RemoveHTTPRoutes() {
	if mgr := httpgateway.Default(); mgr != nil {
		mgr.Remove(s.ID())
	}
}
