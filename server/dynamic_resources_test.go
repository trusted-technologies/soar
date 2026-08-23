package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pterodactyl/wings/environment"
	"github.com/pterodactyl/wings/events"
)

// mockEnv is a minimal ProcessEnvironment used to exercise the dynamic
// resource controller without Docker. It records every settings update so
// tests can assert which tier was actually pushed to the environment.
type mockEnv struct {
	mu      sync.Mutex
	cfg     *environment.Configuration
	state   string
	updates []environment.Limits
}

func newMockEnv(build environment.Limits) *mockEnv {
	return &mockEnv{
		cfg: environment.NewConfiguration(environment.Settings{Limits: build}, nil),
	}
}

func (m *mockEnv) Type() string                            { return "mock" }
func (m *mockEnv) Config() *environment.Configuration      { return m.cfg }
func (m *mockEnv) Events() *events.Bus                     { return events.NewBus() }
func (m *mockEnv) Exists() (bool, error)                   { return true, nil }
func (m *mockEnv) IsRunning(ctx context.Context) (bool, error) { return m.State() == environment.ProcessRunningState, nil }
func (m *mockEnv) OnBeforeStart(ctx context.Context) error { return nil }
func (m *mockEnv) Start(ctx context.Context) error         { return nil }
func (m *mockEnv) Stop(ctx context.Context) error          { return nil }
func (m *mockEnv) WaitForStop(ctx context.Context, d time.Duration, terminate bool) error { return nil }
func (m *mockEnv) Terminate(ctx context.Context, signal string) error { return nil }
func (m *mockEnv) Destroy() error                          { return nil }
func (m *mockEnv) ExitState() (uint32, bool, error)        { return 0, false, nil }
func (m *mockEnv) Create() error                           { return nil }
func (m *mockEnv) Attach(ctx context.Context) error        { return nil }
func (m *mockEnv) SendCommand(s string) error              { return nil }
func (m *mockEnv) Readlog(lines int) ([]string, error)     { return nil, nil }
func (m *mockEnv) Uptime(ctx context.Context) (int64, error) { return 0, nil }
func (m *mockEnv) SetLogCallback(f func([]byte))           {}

func (m *mockEnv) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *mockEnv) SetState(s string) {
	m.mu.Lock()
	m.state = s
	m.mu.Unlock()
}

// InSituUpdate records the limits that would be applied to a live container.
func (m *mockEnv) InSituUpdate() error {
	m.mu.Lock()
	m.updates = append(m.updates, m.cfg.Limits())
	m.mu.Unlock()
	return nil
}

func (m *mockEnv) lastLimits() (int64, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.updates) == 0 {
		return -1, -1
	}
	l := m.updates[len(m.updates)-1]
	return l.CpuLimit, l.MemoryLimit
}

func newTestServer(t *testing.T, build environment.Limits, policy DynamicResourcePolicy, env environment.ProcessEnvironment) *Server {
	t.Helper()
	s, err := New(nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	s.Environment = env
	s.cfg.Uuid = "test-uuid"
	s.cfg.Build = build
	s.cfg.DynamicResources = policy
	return s
}

var fullPolicy = DynamicResourcePolicy{
	Enabled: true, MinCpuLimit: 100, MaxCpuLimit: 800, CpuStep: 100,
	MinMemoryLimit: 1024, MaxMemoryLimit: 8192, MemoryStep: 1024,
	ScaleUpSeconds: 30, ScaleDownSeconds: 300,
}

// mib converts a (possibly fractional) MiB value to bytes.
func mib(v float64) uint64 { return uint64(v * bytesPerMiB) }

// A server booting with dynamic resources enabled must start at the minimum
// tier and keep it across syncs while utilization is low.
func TestDynamicResourcesStartAtMinimumAndPreserveTier(t *testing.T) {
	build := environment.Limits{CpuLimit: 800, MemoryLimit: 8192}
	env := newMockEnv(build)
	s := newTestServer(t, build, fullPolicy, env)
	s.Environment.SetState(environment.ProcessRunningState)

	// The controller starts at the minimum tier (applied at boot by
	// SyncWithEnvironment, which reads dynamic.current()). Observations with
	// low load must never push a redundant InSituUpdate.
	controller := &s.dynamic
	reconciled := controller.reconcile(fullPolicy, build)
	if reconciled.CpuLimit != 100 || reconciled.MemoryLimit != 1024 {
		t.Fatalf("expected reconciled build limits at minimum tier, got %+v", reconciled)
	}
	s.ObserveDynamicResources(environment.Stats{CpuAbsolute: 1, Memory: uint64(128 * bytesPerMiB)})

	if cpu, memory := env.lastLimits(); cpu != -1 || memory != -1 {
		t.Fatalf("expected no InSituUpdate for idle server at minimum tier, got cpu=%d memory=%d", cpu, memory)
	}

	// A second low-load observation must not change anything either.
	s.ObserveDynamicResources(environment.Stats{CpuAbsolute: 1, Memory: uint64(128 * bytesPerMiB)})
	if cpu, memory := env.lastLimits(); cpu != -1 || memory != -1 {
		t.Fatalf("expected tier preserved, got cpu=%d memory=%d", cpu, memory)
	}
}

// An invalid policy must fall back to static build limits and never touch the
// environment.
func TestInvalidDynamicPolicyFallsBackToStaticBuild(t *testing.T) {
	build := environment.Limits{CpuLimit: 400, MemoryLimit: 4096}
	env := newMockEnv(build)
	policy := DynamicResourcePolicy{
		Enabled: true, MinCpuLimit: 500, MaxCpuLimit: 400, CpuStep: 100,
		MinMemoryLimit: 1024, MaxMemoryLimit: 4096, MemoryStep: 512,
	}
	s := newTestServer(t, build, policy, env)
	s.Environment.SetState(environment.ProcessRunningState)

	s.dynamic.reconcile(policy, build)
	s.ObserveDynamicResources(environment.Stats{CpuAbsolute: 99, Memory: uint64(4095 * bytesPerMiB)})

	if updates := len(env.updates); updates != 0 {
		t.Fatalf("expected no InSituUpdate calls for invalid policy, got %d", updates)
	}
}

// Observations for an offline server are ignored entirely.
func TestDynamicResourcesIgnoreOfflineServers(t *testing.T) {
	build := environment.Limits{CpuLimit: 800, MemoryLimit: 8192}
	env := newMockEnv(build)
	s := newTestServer(t, build, fullPolicy, env)

	s.dynamic.reconcile(fullPolicy, build)
	s.ObserveDynamicResources(environment.Stats{CpuAbsolute: 99, Memory: uint64(8191 * bytesPerMiB)})

	if len(env.updates) != 0 {
		t.Fatalf("expected no updates for offline server, got %d", len(env.updates))
	}
}

// Memory pressure past 95% of the tier must scale up immediately — the kernel
// OOM killer does not wait for ScaleUpSeconds.
func TestDynamicResourcesEmergencyMemoryScaleUp(t *testing.T) {
	build := environment.Limits{CpuLimit: 800, MemoryLimit: 8192}
	env := newMockEnv(build)
	s := newTestServer(t, build, fullPolicy, env)
	s.Environment.SetState(environment.ProcessRunningState)
	s.dynamic.reconcile(fullPolicy, build)

	// First hot observation (90-95%) only arms the timer.
	s.ObserveDynamicResources(environment.Stats{
		CpuAbsolute: 0, Memory: mib(1024 * 0.92),
	})
	if cpu, _ := env.lastLimits(); cpu != -1 {
		t.Fatal("expected timer-only arm on first hot sample")
	}

	// Past 95% the tier must jump without waiting for ScaleUpSeconds.
	s.ObserveDynamicResources(environment.Stats{
		CpuAbsolute: 0, Memory: mib(1024 * 0.96),
	})
	cpu, memory := env.lastLimits()
	if cpu != 100 || memory != 2048 {
		t.Fatalf("expected emergency scale-up to 2048 MiB, got cpu=%d memory=%d", cpu, memory)
	}

	// CPU pressure alone must still respect the timer.
	s.ObserveDynamicResources(environment.Stats{
		CpuAbsolute: 95, Memory: mib(2048 * 0.50),
	})
	cpu, memory = env.lastLimits()
	if cpu != 100 || memory != 2048 {
		t.Fatalf("cpu should stay at current tier until timer expires, got cpu=%d memory=%d", cpu, memory)
	}
}

// Sustained high load past ScaleUpSeconds must scale up through InSituUpdate.
func TestDynamicResourcesTimerBasedScaleUp(t *testing.T) {
	build := environment.Limits{CpuLimit: 800, MemoryLimit: 8192}
	env := newMockEnv(build)
	policy := fullPolicy
	policy.ScaleUpSeconds = 1
	policy.ScaleDownSeconds = 1
	s := newTestServer(t, build, policy, env)
	s.Environment.SetState(environment.ProcessRunningState)
	s.dynamic.reconcile(policy, build)

	hot := environment.Stats{CpuAbsolute: 95, Memory: mib(1024 * 0.92)}
	s.ObserveDynamicResources(hot)
	if _, memory := env.lastLimits(); memory != -1 {
		t.Fatal("no scale-up expected before ScaleUpSeconds elapses")
	}

	time.Sleep(1100 * time.Millisecond)
	s.ObserveDynamicResources(hot)

	cpu, memory := env.lastLimits()
	if cpu != 200 || memory != 2048 {
		t.Fatalf("expected scale-up to cpu=200 memory=2048 after timer, got cpu=%d memory=%d", cpu, memory)
	}
}

// Low sustained load past ScaleDownSeconds must scale back down.
func TestDynamicResourcesScaleDown(t *testing.T) {
	build := environment.Limits{CpuLimit: 800, MemoryLimit: 8192}
	env := newMockEnv(build)
	policy := fullPolicy
	policy.ScaleUpSeconds = 1
	policy.ScaleDownSeconds = 1
	s := newTestServer(t, build, policy, env)
	s.Environment.SetState(environment.ProcessRunningState)

	// Seed the controller at a higher tier (reconcile first so the policy is
	// armed — without it ObserveDynamicResources returns early).
	s.dynamic.reconcile(policy, build)
	s.dynamic.cpu, s.dynamic.memory = 400, 4096

	idle := environment.Stats{CpuAbsolute: 1, Memory: uint64(256 * bytesPerMiB)}
	s.ObserveDynamicResources(idle)
	if _, memory := env.lastLimits(); memory != -1 {
		t.Fatal("no scale-down expected before ScaleDownSeconds elapses")
	}

	time.Sleep(1100 * time.Millisecond)
	s.ObserveDynamicResources(idle)

	cpu, memory := env.lastLimits()
	if cpu != 300 || memory != 3072 {
		t.Fatalf("expected one step down to cpu=300 memory=3072, got cpu=%d memory=%d", cpu, memory)
	}
}
