package l7

import (
	"sync"
	"time"
)

// mitigationDecay is how long enhanced filtering stays active after the last
// time the CPS threshold was exceeded.
const mitigationDecay = 2 * time.Minute

// verifyWindow is the window in which a reconnect challenge must be answered.
const verifyWindow = 60 * time.Second

type ipState struct {
	sessions       int
	lastDisconnect time.Time
	lastSeen       time.Time
	loginTimes     []time.Time
	statusTimes    []time.Time
	verifiedUntil  time.Time
	bannedUntil    time.Time
	challengedAt   time.Time
	statusSeen     bool
	strikes        int
}

// cpsCounter tracks connections per second using the current and the previous
// one-second bucket.
type cpsCounter struct {
	sec  int64
	cur  int
	prev int
}

func (c *cpsCounter) hit(now time.Time) int {
	s := now.Unix()
	if s != c.sec {
		if s == c.sec+1 {
			c.prev = c.cur
		} else {
			c.prev = 0
		}
		c.cur = 0
		c.sec = s
	}
	c.cur++
	if c.cur > c.prev {
		return c.cur
	}
	return c.prev
}

func (c *cpsCounter) current(now time.Time) int {
	s := now.Unix()
	switch {
	case s == c.sec:
		if c.cur > c.prev {
			return c.cur
		}
		return c.prev
	case s == c.sec+1:
		return c.cur
	default:
		return 0
	}
}

type tracker struct {
	mu              sync.Mutex
	ips             map[string]*ipState
	cps             cpsCounter
	mitigationUntil time.Time
}

func newTracker() *tracker {
	return &tracker{ips: make(map[string]*ipState)}
}

func (t *tracker) state(ip string) *ipState {
	st, ok := t.ips[ip]
	if !ok {
		st = &ipState{}
		t.ips[ip] = st
	}
	st.lastSeen = time.Now()
	return st
}

// hit registers a new inbound connection and reports the current CPS along
// with whether mitigation is currently active for the given settings.
func (t *tracker) hit(s Settings) (cps int, mitigation bool) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	cps = t.cps.hit(now)
	if s.AutoMitigation && cps > s.CPSThreshold {
		t.mitigationUntil = now.Add(mitigationDecay)
	}
	mitigation = s.Mode == "always" || now.Before(t.mitigationUntil)
	return cps, mitigation
}

func (t *tracker) snapshot(s Settings) (cps int, mitigation bool, verified, banned, tracked int) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	cps = t.cps.current(now)
	mitigation = s.Mode == "always" || now.Before(t.mitigationUntil)
	for _, st := range t.ips {
		if now.Before(st.verifiedUntil) {
			verified++
		}
		if now.Before(st.bannedUntil) {
			banned++
		}
	}
	tracked = len(t.ips)
	return
}

func (t *tracker) isBanned(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.ips[ip]
	return ok && time.Now().Before(st.bannedUntil)
}

func (t *tracker) ban(ip string, seconds int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(ip)
	st.bannedUntil = time.Now().Add(time.Duration(seconds) * time.Second)
}

// allow marks an address as verified for the given number of seconds.
func (t *tracker) allow(ip string, seconds int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(ip)
	st.verifiedUntil = time.Now().Add(time.Duration(seconds) * time.Second)
	st.challengedAt = time.Time{}
	st.strikes = 0
	st.bannedUntil = time.Time{}
}

func (t *tracker) isVerified(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.ips[ip]
	return ok && time.Now().Before(st.verifiedUntil)
}

// openSession registers a connection for the session-per-IP accounting and
// reports whether the limit was exceeded. The caller must always pair this
// with closeSession.
func (t *tracker) openSession(ip string, max int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(ip)
	st.sessions++
	return st.sessions <= max
}

func (t *tracker) closeSession(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if st, ok := t.ips[ip]; ok {
		if st.sessions > 0 {
			st.sessions--
		}
		st.lastDisconnect = time.Now()
	}
}

// inReconnectCooldown reports whether the address reconnected too quickly
// after its previous disconnect. Verified addresses are exempt: the cooldown
// exists to slow down bots, not players that already proved themselves.
func (t *tracker) inReconnectCooldown(ip string, seconds int) bool {
	if seconds <= 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.ips[ip]
	if !ok || st.lastDisconnect.IsZero() {
		return false
	}
	if time.Now().Before(st.verifiedUntil) {
		return false
	}
	return time.Since(st.lastDisconnect) < time.Duration(seconds)*time.Second
}

// loginAllowed enforces the per-IP login rate limit (a sliding one second
// window). A zero limit disables the check.
func (t *tracker) loginAllowed(ip string, perSecond int) bool {
	if perSecond <= 0 {
		return true
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(ip)
	st.loginTimes = pruneTimes(st.loginTimes, now, time.Second)
	if len(st.loginTimes) >= perSecond {
		return false
	}
	st.loginTimes = append(st.loginTimes, now)
	return true
}

// statusAllowed rate-limits status (ping) requests per address: at most 20 in
// a five second window, which is far above anything a legitimate client does.
func (t *tracker) statusAllowed(ip string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(ip)
	st.statusTimes = pruneTimes(st.statusTimes, now, 5*time.Second)
	if len(st.statusTimes) >= 20 {
		return false
	}
	st.statusTimes = append(st.statusTimes, now)
	st.statusSeen = true
	return true
}

func (t *tracker) hasStatusSeen(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.ips[ip]
	return ok && st.statusSeen
}

// completeChallenge reports whether an outstanding reconnect challenge was
// answered in time. When it was, the address becomes verified.
func (t *tracker) completeChallenge(ip string, allowSeconds int) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.ips[ip]
	if !ok || st.challengedAt.IsZero() {
		return false
	}
	if now.Sub(st.challengedAt) > verifyWindow {
		return false
	}
	st.verifiedUntil = now.Add(time.Duration(allowSeconds) * time.Second)
	st.challengedAt = time.Time{}
	st.strikes = 0
	return true
}

// challenge records that a reconnect challenge was issued and returns the
// number of times this address has been challenged without verifying.
func (t *tracker) challenge(ip string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.state(ip)
	st.challengedAt = time.Now()
	st.strikes++
	return st.strikes
}

// currentStrikes reports how many times the address has been challenged
// without verifying.
func (t *tracker) currentStrikes(ip string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if st, ok := t.ips[ip]; ok {
		return st.strikes
	}
	return 0
}

func pruneTimes(times []time.Time, now time.Time, window time.Duration) []time.Time {
	out := times[:0]
	for _, ts := range times {
		if now.Sub(ts) < window {
			out = append(out, ts)
		}
	}
	return out
}

// prune removes idle address entries. Called periodically by the proxy.
func (t *tracker) prune() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, st := range t.ips {
		if st.sessions > 0 {
			continue
		}
		if now.Before(st.bannedUntil) || now.Before(st.verifiedUntil) {
			continue
		}
		if now.Sub(st.lastSeen) > 30*time.Minute {
			delete(t.ips, ip)
		}
	}
}
