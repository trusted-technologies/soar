package docker

import (
	"testing"

	"github.com/pterodactyl/wings/environment"
	"github.com/pterodactyl/wings/remote"
)

func testEnvironment(id string, m *Metadata) *Environment {
	return &Environment{
		Id:            id,
		Configuration: environment.NewConfiguration(environment.Settings{}, nil),
		meta:          m,
	}
}

// buildMounts must never add a rootfs mount in any mode. The Docker API
// rejects volume mounts targeting "/", so a persistent rootfs is realized as
// the container's writable layer (kept alive across power cycles), not as a
// mount.
func TestBuildMounts(t *testing.T) {
	tests := []struct {
		name string
		meta *Metadata
	}{
		{name: "preset mode", meta: &Metadata{Image: "img"}},
		{
			name: "instance mode with persistent rootfs adds no volume mount",
			meta: &Metadata{
				Image:                  "img",
				ExecutionMode:          remote.ExecutionModeInstance,
				PersistentRootfs:       true,
				RootfsStorageReference: "rootfs:test-uuid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testEnvironment("srv-fallback", tt.meta)
			mounts := e.buildMounts()
			if len(mounts) != 0 {
				t.Fatalf("len(mounts) = %d, want 0 (no rootfs mount allowed)", len(mounts))
			}
		})
	}
}

// The contract accessors must normalize an unset mode to preset so that
// metadata coming from legacy panels behaves like the classic flow.
func TestSetExecutionContractNormalization(t *testing.T) {
	e := testEnvironment("srv-norm", &Metadata{Image: "img"})

	e.SetExecutionContract("", false, "")
	mode, persistent, ref := e.ExecutionContract()
	if mode != remote.ExecutionModePreset || persistent || ref != "" {
		t.Fatalf("empty contract = (%q, %v, %q), want preset/false/empty", mode, persistent, ref)
	}

	e.SetExecutionContract(remote.ExecutionModeInstance, true, "rootfs:abc")
	mode, persistent, ref = e.ExecutionContract()
	if mode != remote.ExecutionModeInstance || !persistent || ref != "rootfs:abc" {
		t.Fatalf("instance contract = (%q, %v, %q)", mode, persistent, ref)
	}
}
