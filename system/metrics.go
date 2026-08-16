package system

import "time"

// NodeMetrics is a compact host-level snapshot exposed to the Soneyko panel.
type NodeMetrics struct {
	CPUPercent       float64   `json:"cpu_percent"`
	MemoryTotalBytes uint64    `json:"memory_total_bytes"`
	MemoryUsedBytes  uint64    `json:"memory_used_bytes"`
	MemoryPercent    float64   `json:"memory_percent"`
	DiskTotalBytes   uint64    `json:"disk_total_bytes"`
	DiskUsedBytes    uint64    `json:"disk_used_bytes"`
	DiskPercent      float64   `json:"disk_percent"`
	NetworkRxBytes   uint64    `json:"network_rx_bytes"`
	NetworkTxBytes   uint64    `json:"network_tx_bytes"`
	NetworkRxBps     float64   `json:"network_rx_bps"`
	NetworkTxBps     float64   `json:"network_tx_bps"`
	SampledAt        time.Time `json:"sampled_at"`
}

func percentage(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}
