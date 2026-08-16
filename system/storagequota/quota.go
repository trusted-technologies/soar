package storagequota

import "time"

type Info struct {
	Mode      string `json:"mode"`
	Status    string `json:"status"`
	CheckedAt string `json:"checked_at"`
}

func info(mode, status string) Info {
	return Info{Mode: mode, Status: status, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
}
