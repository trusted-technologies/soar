package l7

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

// captchaTTL is how long an issued captcha code remains valid.
const captchaTTL = 10 * time.Minute

type captchaEntry struct {
	nodeID  string
	uuid    string
	ip      string
	expires time.Time
}

// captchaStore maps opaque codes handed to players to the address that must be
// verified once the browser challenge is solved.
type captchaStore struct {
	mu      sync.Mutex
	entries map[string]captchaEntry
}

func newCaptchaStore() *captchaStore {
	s := &captchaStore{entries: make(map[string]captchaEntry)}
	go s.gcLoop()
	return s
}

func (s *captchaStore) issue(nodeID, uuid, ip string) string {
	for {
		// Keep the public code at exactly eight URL-safe characters. The first
		// two characters route the verification request to the issuing node and
		// the remaining six carry 36 random bits. Codes are short-lived,
		// single-use, and can only be redeemed after Turnstile succeeds.
		var b [5]byte
		if _, err := rand.Read(b[:]); err != nil {
			continue
		}
		code := captchaNodePrefix(nodeID) + base64.RawURLEncoding.EncodeToString(b[:])[:6]

		s.mu.Lock()
		if _, exists := s.entries[code]; exists {
			s.mu.Unlock()
			continue
		}
		s.entries[code] = captchaEntry{nodeID: nodeID, uuid: uuid, ip: ip, expires: time.Now().Add(captchaTTL)}
		s.mu.Unlock()
		return code
	}
}

// captchaNodePrefix mirrors the panel's node selector. Node IDs are UUIDs in
// normal installations; removing separators keeps the code compact while
// still narrowing verification to a single node in almost every deployment.
func captchaNodePrefix(nodeID string) string {
	id := strings.ToLower(strings.ReplaceAll(nodeID, "-", ""))
	if len(id) >= 2 {
		return id[:2]
	}
	return (id + "00")[:2]
}

// resolve consumes a captcha code, returning the server UUID and address it
// was issued for. The second return is false when the code is unknown/expired.
func (s *captchaStore) resolve(code string) (uuid, ip string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.entries[code]
	if !found || time.Now().After(e.expires) {
		delete(s.entries, code)
		return "", "", false
	}
	delete(s.entries, code)
	return e.uuid, e.ip, true
}

func (s *captchaStore) gcLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for code, e := range s.entries {
			if now.After(e.expires) {
				delete(s.entries, code)
			}
		}
		s.mu.Unlock()
	}
}
