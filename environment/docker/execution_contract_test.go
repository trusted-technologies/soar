package docker

import (
	"testing"

	"github.com/docker/docker/api/types/mount"

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

// buildMounts must leave preset-mode mounts untouched and prepend the named
// rootfs volume only under a persistent-rootfs contract.
func TestBuildMounts(t *testing.T) {
	tests := []struct {
		name           string
		meta           *Metadata
		wantRootfsVol  string
		wantMountCount int
	}{
		{
			name:           "preset mode has no rootfs volume",
			meta:           &Metadata{Image: "img"},
			wantRootfsVol:  "",
			wantMountCount: 0,
		},
		{
			name: "instance mode mounts named rootfs volume",
			meta: &Metadata{
				Image:                  "img",
				ExecutionMode:          remote.ExecutionModeInstance,
				PersistentRootfs:       true,
				RootfsStorageReference: "rootfs:test-uuid",
			},
			wantRootfsVol:  "rootfs:test-uuid",
			wantMountCount: 1,
		},
		{
			name: "empty storage reference falls back to container id",
			meta: &Metadata{
				Image:            "img",
				ExecutionMode:    remote.ExecutionModeInstance,
				PersistentRootfs: true,
			},
			wantRootfsVol:  "rootfs:srv-fallback",
			wantMountCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testEnvironment("srv-fallback", tt.meta)
			mounts := e.buildMounts()

			if len(mounts) != tt.wantMountCount {
				t.Fatalf("len(mounts) = %d, want %d", len(mounts), tt.wantMountCount)
			}

			if tt.wantRootfsVol == "" {
				return
			}

			m := mounts[0]
			if m.Type != mount.TypeVolume || m.Source != tt.wantRootfsVol || m.Target != "/" {
				t.Fatalf("first mount = %+v, want volume %q at /", m, tt.wantRootfsVol)
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
