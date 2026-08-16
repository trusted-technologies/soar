//go:build !linux

package storagequota

func Detect(_ string) Info { return info("none", "unsupported") }

func Apply(_, _ string, _ int64) error { return nil }
