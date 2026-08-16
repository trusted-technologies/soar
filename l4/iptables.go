package l4

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"os/exec"
	"strings"
	"sync"
)

// table and base chain used by every L4 rule. mangle PREROUTING is chosen
// deliberately: it sees inbound packets before Docker's nat DNAT rewrites the
// destination, so a rule matching "-d <public-ip> --dport <port>" covers both
// the container's published port and any L7 proxy socket listening on the host.
const (
	tableMangle = "mangle"
	baseChain   = "SOAR-L4"
	parentChain = "PREROUTING"
)

// iptables serialises access to the iptables binary. iptables itself is not
// safe to run concurrently (hence the -w lock flag) and we additionally keep a
// process-level mutex so reconciles from different servers never interleave.
type iptables struct {
	mu   sync.Mutex
	bin  string
	ok   bool
	once sync.Once
}

func newIPTables() *iptables { return &iptables{} }

// available resolves the iptables binary once and caches whether it can be used
// on this node. When absent (e.g. an unsupported platform) every operation
// becomes a no-op so the daemon keeps running.
func (t *iptables) available() bool {
	t.once.Do(func() {
		if p, err := exec.LookPath("iptables"); err == nil {
			t.bin = p
			t.ok = true
		}
	})
	return t.ok
}

// run executes a single iptables command in the mangle table. The -w flag makes
// iptables wait for the xtables lock instead of failing when another process
// holds it.
func (t *iptables) run(args ...string) (string, error) {
	if !t.available() {
		return "", errUnavailable
	}
	full := append([]string{"-w", "5", "-t", tableMangle}, args...)
	cmd := exec.Command(t.bin, full...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("iptables %s: %v: %s", strings.Join(full, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// tryRun runs a command and swallows the error. Used for best-effort teardown
// where a missing rule/chain is an expected outcome.
func (t *iptables) tryRun(args ...string) { _, _ = t.run(args...) }

// chainExists reports whether a chain is already defined in the mangle table.
func (t *iptables) chainExists(chain string) bool {
	_, err := t.run("-n", "-L", chain)
	return err == nil
}

// ensureChain creates a chain if it does not already exist.
func (t *iptables) ensureChain(chain string) error {
	if t.chainExists(chain) {
		return nil
	}
	_, err := t.run("-N", chain)
	return err
}

// dropChain flushes and deletes a chain, ignoring "does not exist" style errors.
func (t *iptables) dropChain(chain string) {
	t.tryRun("-F", chain)
	t.tryRun("-X", chain)
}

// ensureRule appends a rule to a chain only when an identical rule is not
// already present (idempotent -A).
func (t *iptables) ensureRule(chain string, rule []string) error {
	check := append([]string{"-C", chain}, rule...)
	if _, err := t.run(check...); err == nil {
		return nil
	}
	add := append([]string{"-A", chain}, rule...)
	_, err := t.run(add...)
	return err
}

// insertRule inserts a rule at the top of a chain when it is not already
// present. Used for the PREROUTING -> SOAR-L4 jump so it runs before other
// mangle rules.
func (t *iptables) insertRule(chain string, rule []string) error {
	check := append([]string{"-C", chain}, rule...)
	if _, err := t.run(check...); err == nil {
		return nil
	}
	ins := append([]string{"-I", chain, "1"}, rule...)
	_, err := t.run(ins...)
	return err
}

// deleteRule removes a single rule, ignoring errors when it is already gone.
func (t *iptables) deleteRule(chain string, rule []string) {
	del := append([]string{"-D", chain}, rule...)
	t.tryRun(del...)
}

// chainName builds a deterministic, iptables-safe chain name (max 28 chars) for
// a server/port/protocol tuple. The CRC keeps it short and stable across
// reconciles so teardown can find the right chain.
func chainName(uuid string, port int, proto string) string {
	sum := crc32.ChecksumIEEE([]byte(fmt.Sprintf("%s/%d/%s", uuid, port, proto)))
	return fmt.Sprintf("SL4%08X", sum)
}

// hashName builds a unique hashlimit bucket name (kernel limit is 15 chars).
func hashName(prefix, chain string) string {
	// chain is "SL4XXXXXXXX" (11 chars); take the 8 hex digits.
	suffix := strings.TrimPrefix(chain, "SL4")
	name := prefix + suffix
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}
