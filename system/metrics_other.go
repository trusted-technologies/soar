//go:build !linux

package system

import "fmt"

func GetNodeMetrics(_ string) (NodeMetrics, error) {
	return NodeMetrics{}, fmt.Errorf("node metrics are only supported on Linux")
}
