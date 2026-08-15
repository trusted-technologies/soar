package l7

import (
	"crypto/rand"
	"encoding/hex"
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
	var b [16]byte
	_, _ = rand.Read(b[:])
	code := nodeID + "-" + hex.EncodeToString(b[:])
	s.mu.Lock()
	s.entries[code] = captchaEntry{nodeID: nodeID, uuid: uuid, ip: ip, expires: time.Now().Add(captchaTTL)}
	s.mu.Unlock()
	return code
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
