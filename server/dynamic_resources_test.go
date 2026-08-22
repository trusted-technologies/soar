package server

import (
	"testing"

	"github.com/pterodactyl/wings/environment"
)

func TestDynamicResourcesStartAtMinimumAndPreserveTier(t *testing.T) {
	build := environment.Limits{CpuLimit: 800, MemoryLimit: 8192}
	policy := DynamicResourcePolicy{
		Enabled: true, MinCpuLimit: 100, MaxCpuLimit: 800, CpuStep: 100,
		MinMemoryLimit: 1024, MaxMemoryLimit: 8192, MemoryStep: 1024,
		ScaleUpSeconds: 30, ScaleDownSeconds: 300,
	}
	var controller dynamicResourceController

	limits := controller.reconcile(policy, build)
	if limits.CpuLimit != 100 || limits.MemoryLimit != 1024 {
		t.Fatalf("expected minimum tier, got cpu=%d memory=%d", limits.CpuLimit, limits.MemoryLimit)
	}

	controller.cpu, controller.memory = 400, 4096
	limits = controller.reconcile(policy, build)
	if limits.CpuLimit != 400 || limits.MemoryLimit != 4096 {
		t.Fatalf("expected current tier to survive sync, got cpu=%d memory=%d", limits.CpuLimit, limits.MemoryLimit)
	}
}

func TestInvalidDynamicPolicyFallsBackToStaticBuild(t *testing.T) {
	build := environment.Limits{CpuLimit: 400, MemoryLimit: 4096}
	policy := DynamicResourcePolicy{
		Enabled: true, MinCpuLimit: 500, MaxCpuLimit: 400, CpuStep: 100,
		MinMemoryLimit: 1024, MaxMemoryLimit: 4096, MemoryStep: 512,
	}
	var controller dynamicResourceController

	limits := controller.reconcile(policy, build)
	if limits.CpuLimit != build.CpuLimit || limits.MemoryLimit != build.MemoryLimit {
		t.Fatalf("expected static build fallback, got cpu=%d memory=%d", limits.CpuLimit, limits.MemoryLimit)
	}
}
