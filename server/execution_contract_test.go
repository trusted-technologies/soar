package server

import (
	"encoding/json"
	"testing"
)

// Contract parsing: settings.container must round-trip the execution contract
// sent by the panel, with legacy payloads (no container object at all) mapping
// to the preset flow.
func TestExecutionContractParsing(t *testing.T) {
	tests := []struct {
		name             string
		payload          string
		wantMode         string
		wantPersistent   bool
		wantStorageRef   string
	}{
		{
			name:           "legacy payload without container",
			payload:        `{"uuid": "1f2a3b4c-0000-4000-8000-000000000001"}`,
			wantMode:       "preset",
			wantPersistent: false,
			wantStorageRef: "rootfs:1f2a3b4c-0000-4000-8000-000000000001",
		},
		{
			name:           "preset mode explicit",
			payload:        `{"uuid": "u-preset", "container": {"image": "ghcr.io/parkervcp/yolks:debian", "execution_mode": "preset"}}`,
			wantMode:       "preset",
			wantPersistent: false,
			wantStorageRef: "rootfs:u-preset",
		},
		{
			name:           "instance mode persistent rootfs",
			payload:        `{"uuid": "u-instance", "container": {"image": "ubuntu:24.04", "execution_mode": "instance", "rootfs": {"persistent": true, "storage_reference": "rootfs:u-instance"}}}`,
			wantMode:       "instance",
			wantPersistent: true,
			wantStorageRef: "rootfs:u-instance",
		},
		{
			name:           "instance mode without storage reference falls back to uuid",
			payload:        `{"uuid": "u-fallback", "container": {"image": "ubuntu:24.04", "execution_mode": "instance", "rootfs": {"persistent": true}}}`,
			wantMode:       "instance",
			wantPersistent: true,
			wantStorageRef: "rootfs:u-fallback",
		},
		{
			name:           "persistent flag ignored outside instance mode",
			payload:        `{"uuid": "u-preset-root", "container": {"image": "img", "execution_mode": "preset", "rootfs": {"persistent": true}}}`,
			wantMode:       "preset",
			wantPersistent: false,
			wantStorageRef: "rootfs:u-preset-root",
		},
		{
			name:           "unknown mode maps to preset",
			payload:        `{"uuid": "u-bogus", "container": {"image": "img", "execution_mode": "chaos"}}`,
			wantMode:       "preset",
			wantPersistent: false,
			wantStorageRef: "rootfs:u-bogus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Configuration
			if err := json.Unmarshal([]byte(tt.payload), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if got := cfg.ExecutionMode(); got != tt.wantMode {
				t.Fatalf("ExecutionMode() = %q, want %q", got, tt.wantMode)
			}
			if got := cfg.PersistentRootfs(); got != tt.wantPersistent {
				t.Fatalf("PersistentRootfs() = %v, want %v", got, tt.wantPersistent)
			}
			if got := cfg.RootfsStorageReference(); got != tt.wantStorageRef {
				t.Fatalf("RootfsStorageReference() = %q, want %q", got, tt.wantStorageRef)
			}
		})
	}
}

// The panel can override the storage reference; it must be passed through
// verbatim so volume identity is stable across nodes and reinstalls.
func TestRootfsStorageReferenceOverride(t *testing.T) {
	var cfg Configuration
	payload := `{"uuid": "u-x", "container": {"execution_mode": "instance", "rootfs": {"persistent": true, "storage_reference": "rootfs:pinned-volume-42"}}}`
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := cfg.RootfsStorageReference(); got != "rootfs:pinned-volume-42" {
		t.Fatalf("RootfsStorageReference() = %q, want pinned override", got)
	}
}
