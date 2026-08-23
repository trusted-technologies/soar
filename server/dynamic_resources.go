package server

import (
	"math"
	"sync"
	"time"

	"github.com/pterodactyl/wings/environment"
)

const bytesPerMiB = 1024 * 1024

type dynamicResourceController struct {
	mu        sync.Mutex
	policy    DynamicResourcePolicy
	cpu       int64
	memory    int64
	upSince   time.Time
	downSince time.Time
}

func normaliseDynamicPolicy(p DynamicResourcePolicy, build environment.Limits) DynamicResourcePolicy {
	if !p.Enabled {
		return DynamicResourcePolicy{}
	}
	p.MaxCpuLimit = minPositive(p.MaxCpuLimit, build.CpuLimit)
	p.MaxMemoryLimit = minPositive(p.MaxMemoryLimit, build.MemoryLimit)
	if p.MinCpuLimit <= 0 || p.MaxCpuLimit < p.MinCpuLimit || p.CpuStep <= 0 ||
		p.MinMemoryLimit <= 0 || p.MaxMemoryLimit < p.MinMemoryLimit || p.MemoryStep <= 0 {
		return DynamicResourcePolicy{}
	}
	if p.ScaleUpSeconds < 1 {
		p.ScaleUpSeconds = 15
	}
	if p.ScaleDownSeconds < 1 {
		p.ScaleDownSeconds = 120
	}
	return p
}

func minPositive(value, fallback int64) int64 {
	if value <= 0 || (fallback > 0 && value > fallback) {
		return fallback
	}
	return value
}

func clampStep(value, minimum, maximum, step int64) int64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	if step <= 0 {
		return value
	}
	return minimum + ((value-minimum)/step)*step
}

func (d *dynamicResourceController) reconcile(policy DynamicResourcePolicy, build environment.Limits) environment.Limits {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := normaliseDynamicPolicy(policy, build)
	d.policy = p
	d.upSince, d.downSince = time.Time{}, time.Time{}
	if !p.Enabled {
		d.cpu, d.memory = build.CpuLimit, build.MemoryLimit
		return build
	}
	if d.cpu == 0 {
		d.cpu = p.MinCpuLimit
	}
	if d.memory == 0 {
		d.memory = p.MinMemoryLimit
	}
	d.cpu = clampStep(d.cpu, p.MinCpuLimit, p.MaxCpuLimit, p.CpuStep)
	d.memory = clampStep(d.memory, p.MinMemoryLimit, p.MaxMemoryLimit, p.MemoryStep)
	build.CpuLimit, build.MemoryLimit = d.cpu, d.memory
	return build
}

func (d *dynamicResourceController) current(build environment.Limits) (int64, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.policy.Enabled {
		return build.CpuLimit, build.MemoryLimit
	}
	return d.cpu, d.memory
}

func (s *Server) ReconcileDynamicResources(policy DynamicResourcePolicy, build environment.Limits) environment.Limits {
	return s.dynamic.reconcile(policy, build)
}

func (s *Server) ObserveDynamicResources(stats environment.Stats) {
	d := &s.dynamic
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.policy
	if !p.Enabled || s.Environment.State() != environment.ProcessRunningState {
		return
	}

	now := time.Now()
	cpuHot := stats.CpuAbsolute >= float64(d.cpu)*0.90
	memoryHot := stats.Memory >= uint64(float64(d.memory*bytesPerMiB)*0.90)
	nextCpu, nextMemory := d.cpu, d.memory
	if cpuHot {
		nextCpu = minInt64(p.MaxCpuLimit, d.cpu+p.CpuStep)
	}
	if memoryHot {
		nextMemory = minInt64(p.MaxMemoryLimit, d.memory+p.MemoryStep)
	}
	if (cpuHot || memoryHot) && (nextCpu > d.cpu || nextMemory > d.memory) {
		d.downSince = time.Time{}
		// Memory pressure past 95% of the tier means the workload is about to
		// be killed by the kernel OOM killer before the regular scale-up timer
		// expires. Burst straight to the next tier instead of waiting — the
		// paid ceiling (build) still bounds every jump.
		if memoryHot && stats.Memory >= uint64(float64(d.memory*bytesPerMiB)*0.95) && nextMemory > d.memory {
			d.applyLocked(s, nextCpu, nextMemory)
			d.upSince = time.Time{}
			return
		}
		if d.upSince.IsZero() {
			d.upSince = now
			return
		}
		if now.Sub(d.upSince) < time.Duration(p.ScaleUpSeconds)*time.Second {
			return
		}
		d.applyLocked(s, nextCpu, nextMemory)
		d.upSince = time.Time{}
		return
	}
	d.upSince = time.Time{}

	prevCpu, prevMemory := d.cpu, d.memory
	candidateCpu := maxInt64(p.MinCpuLimit, d.cpu-p.CpuStep)
	candidateMemory := maxInt64(p.MinMemoryLimit, d.memory-p.MemoryStep)
	// Keep 25% memory headroom and require CPU to be comfortably below the
	// candidate lower tier before starting the downscale timer.
	if candidateCpu < d.cpu && stats.CpuAbsolute <= math.Max(1, float64(candidateCpu)*0.60) {
		prevCpu = candidateCpu
	}
	if candidateMemory < d.memory && stats.Memory <= uint64(float64(candidateMemory*bytesPerMiB)*0.75) {
		prevMemory = candidateMemory
	}
	if prevCpu < d.cpu || prevMemory < d.memory {
		if d.downSince.IsZero() {
			d.downSince = now
			return
		}
		if now.Sub(d.downSince) < time.Duration(p.ScaleDownSeconds)*time.Second {
			return
		}
		d.applyLocked(s, prevCpu, prevMemory)
		d.downSince = time.Time{}
	} else {
		d.downSince = time.Time{}
	}
}

func (d *dynamicResourceController) applyLocked(s *Server, cpu, memory int64) {
	if cpu == d.cpu && memory == d.memory {
		return
	}
	cfg := s.Config()
	limits := cfg.Build
	limits.CpuLimit, limits.MemoryLimit = cpu, memory
	s.Environment.Config().SetSettings(environment.Settings{
		Mounts: s.Mounts(), Allocations: cfg.Allocations, Limits: limits, Labels: cfg.Labels,
	})
	if err := s.Environment.InSituUpdate(); err != nil {
		s.Log().WithField("error", err).Warn("failed to apply dynamic resource tier")
		return
	}
	d.cpu, d.memory = cpu, memory
	s.Log().WithField("cpu_limit", cpu).WithField("memory_limit_mb", memory).Info("applied dynamic resource tier")
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
