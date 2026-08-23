package server

import (
	"sync"

	"github.com/pterodactyl/wings/environment"
	"github.com/pterodactyl/wings/remote"
)

type EggConfiguration struct {
	// The internal UUID of the Egg on the Panel.
	ID string `json:"id"`

	// Maintains a list of files that are blacklisted for opening/editing/downloading
	// or basically any type of access on the server by any user. This is NOT the same
	// as a per-user denylist, this is defined at the Egg level.
	FileDenylist []string `json:"file_denylist"`
}

type ConfigurationMeta struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Configuration struct {
	mu sync.RWMutex

	// The unique identifier for the server that should be used when referencing
	// it against the Panel API (and internally). This will be used when naming
	// docker containers as well as in log output.
	Uuid string `json:"uuid"`

	Meta ConfigurationMeta `json:"meta"`

	// Whether or not the server is in a suspended state. Suspended servers cannot
	// be started or modified except in certain scenarios by an admin user.
	Suspended bool `json:"suspended"`

	// The command that should be used when booting up the server instance.
	Invocation string `json:"invocation"`

	// By default this is false, however if selected within the Panel while installing or re-installing a
	// server, specific installation scripts will be skipped for the server process.
	SkipEggScripts bool `json:"skip_egg_scripts"`

	// An array of environment variables that should be passed along to the running
	// server process.
	EnvVars environment.Variables `json:"environment"`

	// Labels is a map of container labels that should be applied to the running server process.
	Labels map[string]string `json:"labels"`

	Allocations           environment.Allocations `json:"allocations"`
	Build                 environment.Limits      `json:"build"`
	DynamicResources      DynamicResourcePolicy   `json:"dynamic_resources,omitempty"`
	CrashDetectionEnabled bool                    `json:"crash_detection_enabled"`
	Mounts                []Mount                 `json:"mounts"`
	Egg                   EggConfiguration        `json:"egg,omitempty"`

	Container ContainerConfiguration `json:"container,omitempty"`
}

// ContainerConfiguration carries the execution contract for the container.
// ExecutionMode selects how the panel resolved this server's spec:
//
//	preset   — classic egg-managed flow (image + egg startup + install scripts)
//	instance — persistent-rootfs workload; install/startup egg scripts skipped
//	image    — direct image launch with a caller-provided command
//
// The zero value ("") is treated as "preset" so legacy panels keep working.
type ContainerConfiguration struct {
	// Defines the Docker image that will be used for this server
	Image string `json:"image,omitempty"`

	// Execution contract mode, see the constants on remote.ExecutionMode*.
	ExecutionMode string `json:"execution_mode,omitempty"`

	// Rootfs describes persistence semantics of the container filesystem.
	Rootfs remote.RootfsConfiguration `json:"rootfs,omitempty"`

	// RequiresRebuild signals the daemon should recreate the container on the
	// next boot even if it already exists (e.g. after a contract change).
	RequiresRebuild bool `json:"requires_rebuild,omitempty"`
}

// ExecutionMode returns the normalized container execution mode; an unset
// value maps to the classic preset flow.
func (c *Configuration) ExecutionMode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch c.Container.ExecutionMode {
	case remote.ExecutionModeInstance:
		return remote.ExecutionModeInstance
	case remote.ExecutionModeImage:
		return remote.ExecutionModeImage
	default:
		return remote.ExecutionModePreset
	}
}

// PersistentRootfs reports whether the container should boot from a persistent
// rootfs volume. Only meaningful in instance mode.
func (c *Configuration) PersistentRootfs() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Container.ExecutionMode == remote.ExecutionModeInstance && c.Container.Rootfs.Persistent
}

// RootfsStorageReference returns the storage backing identifier for a
// persistent rootfs (e.g. "rootfs:<uuid>"), or an empty string.
func (c *Configuration) RootfsStorageReference() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Container.Rootfs.StorageReference == "" {
		return "rootfs:" + c.Uuid
	}
	return c.Container.Rootfs.StorageReference
}

// Server-level accessors mirroring the Configuration helpers so callers that
// hold a *Server don't need to reach into Config() directly.

// ExecutionMode returns the normalized container execution mode.
func (s *Server) ExecutionMode() string {
	return s.Config().ExecutionMode()
}

// PersistentRootfs reports whether this server boots from a persistent rootfs.
func (s *Server) PersistentRootfs() bool {
	return s.Config().PersistentRootfs()
}

// RootfsStorageReference returns the persistent rootfs storage identifier.
func (s *Server) RootfsStorageReference() string {
	return s.Config().RootfsStorageReference()
}

// DynamicResourcePolicy describes live CPU and memory scaling. Build remains
// the capacity reservation (and upper bound); disk is deliberately static.
type DynamicResourcePolicy struct {
	Enabled          bool  `json:"enabled"`
	MinCpuLimit      int64 `json:"min_cpu_limit"`
	MaxCpuLimit      int64 `json:"max_cpu_limit"`
	CpuStep          int64 `json:"cpu_step"`
	MinMemoryLimit   int64 `json:"min_memory_limit"`
	MaxMemoryLimit   int64 `json:"max_memory_limit"`
	MemoryStep       int64 `json:"memory_step"`
	ScaleUpSeconds   int64 `json:"scale_up_seconds"`
	ScaleDownSeconds int64 `json:"scale_down_seconds"`
}

func (s *Server) Config() *Configuration {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return &s.cfg
}

// DiskSpace returns the amount of disk space available to a server in bytes.
func (s *Server) DiskSpace() int64 {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return s.cfg.Build.DiskSpace * 1024.0 * 1024.0
}

func (s *Server) MemoryLimit() int64 {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return s.cfg.Build.MemoryLimit
}

func (c *Configuration) GetUuid() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Uuid
}

func (c *Configuration) SetSuspended(s bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Suspended = s
}
