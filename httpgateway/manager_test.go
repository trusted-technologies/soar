package httpgateway

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeHTTPRoutesByHostAndPreservesForwardingHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "map.example.com" {
			t.Fatalf("expected original host, got %q", request.Host)
		}
		if request.Header.Get("X-Forwarded-Host") != "map.example.com" {
			t.Fatalf("expected forwarded host, got %q", request.Header.Get("X-Forwarded-Host"))
		}
		if request.Header.Get("X-Forwarded-Proto") != "http" {
			t.Fatalf("expected forwarded protocol, got %q", request.Header.Get("X-Forwarded-Proto"))
		}
		_, _ = io.WriteString(writer, "dynmap")
	}))
	defer upstream.Close()

	target := strings.TrimPrefix(upstream.URL, "http://")
	host, portText, _ := strings.Cut(target, ":")
	port := 0
	for _, char := range portText {
		port = port*10 + int(char-'0')
	}
	m := &Manager{routes: map[string]*compiledRoute{}}
	route := Route{Domain: "map.example.com", UpstreamHost: host, UpstreamPort: port}
	m.routes[route.Domain] = newCompiledRoute(route)

	request := httptest.NewRequest(http.MethodGet, "http://map.example.com/world/", nil)
	request.Host = "map.example.com"
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "dynmap" {
		t.Fatalf("unexpected response: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestServeHTTPRejectsUnknownHost(t *testing.T) {
	m := &Manager{routes: map[string]*compiledRoute{}}
	request := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}

func TestWrapPreservesSoarAPIForUnknownHost(t *testing.T) {
	m := &Manager{routes: map[string]*compiledRoute{}}
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "https://node.example.com/api/system", nil)
	recorder := httptest.NewRecorder()
	m.Wrap(next).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected request to reach Soar API handler, got %d", recorder.Code)
	}
}

func TestGetCertificateFallsBackForNodeHostname(t *testing.T) {
	m := &Manager{routes: map[string]*compiledRoute{}}
	certificate, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "node.example.com"})
	if err != nil || certificate != nil {
		t.Fatalf("expected static certificate fallback, got certificate=%v error=%v", certificate, err)
	}
}
