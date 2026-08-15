//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var nodeMetricSample struct {
	sync.Mutex
	cpuTotal uint64
	cpuIdle  uint64
	rxBytes  uint64
	txBytes  uint64
	at       time.Time
}

func readCPU() (uint64, uint64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, 0, fmt.Errorf("/proc/stat has no cpu row")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("invalid /proc/stat cpu row")
	}
	var values []uint64
	for _, field := range fields[1:] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle, nil
}

func readMemory() (uint64, uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil {
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if total == 0 {
		return 0, 0, fmt.Errorf("MemTotal is missing")
	}
	return total, total - min(total, available), scanner.Err()
}

func readNetwork() (uint64, uint64, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	var rx, tx uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		received, rxErr := strconv.ParseUint(fields[0], 10, 64)
		transmitted, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr == nil {
			rx += received
		}
		if txErr == nil {
			tx += transmitted
		}
	}
	return rx, tx, scanner.Err()
}

func GetNodeMetrics(path string) (NodeMetrics, error) {
	now := time.Now().UTC()
	totalCPU, idleCPU, err := readCPU()
	if err != nil {
		return NodeMetrics{}, err
	}
	memoryTotal, memoryUsed, err := readMemory()
	if err != nil {
		return NodeMetrics{}, err
	}
	var disk syscall.Statfs_t
	if err = syscall.Statfs(path, &disk); err != nil {
		return NodeMetrics{}, err
	}
	diskTotal := disk.Blocks * uint64(disk.Bsize)
	diskAvailable := disk.Bavail * uint64(disk.Bsize)
	diskUsed := diskTotal - min(diskTotal, diskAvailable)
	rx, tx, err := readNetwork()
	if err != nil {
		return NodeMetrics{}, err
	}

	nodeMetricSample.Lock()
	defer nodeMetricSample.Unlock()
	cpuPercent := percentage(totalCPU-idleCPU, totalCPU)
	rxBps, txBps := 0.0, 0.0
	if !nodeMetricSample.at.IsZero() {
		if deltaTotal := totalCPU - nodeMetricSample.cpuTotal; deltaTotal > 0 {
			cpuPercent = percentage(deltaTotal-(idleCPU-nodeMetricSample.cpuIdle), deltaTotal)
		}
		seconds := now.Sub(nodeMetricSample.at).Seconds()
		if seconds > 0 {
			// Interfaces can disappear or counters can reset. Treat that sample
			// as zero traffic instead of overflowing an unsigned subtraction.
			if rx >= nodeMetricSample.rxBytes {
				rxBps = float64(rx-nodeMetricSample.rxBytes) / seconds
			}
			if tx >= nodeMetricSample.txBytes {
				txBps = float64(tx-nodeMetricSample.txBytes) / seconds
			}
		}
	}
	nodeMetricSample.cpuTotal, nodeMetricSample.cpuIdle = totalCPU, idleCPU
	nodeMetricSample.rxBytes, nodeMetricSample.txBytes, nodeMetricSample.at = rx, tx, now
	return NodeMetrics{
		CPUPercent:       cpuPercent,
		MemoryTotalBytes: memoryTotal,
		MemoryUsedBytes:  memoryUsed,
		MemoryPercent:    percentage(memoryUsed, memoryTotal),
		DiskTotalBytes:   diskTotal,
		DiskUsedBytes:    diskUsed,
		DiskPercent:      percentage(diskUsed, diskTotal),
		NetworkRxBytes:   rx,
		NetworkTxBytes:   tx,
		NetworkRxBps:     rxBps,
		NetworkTxBps:     txBps,
		SampledAt:        now,
	}, nil
}
