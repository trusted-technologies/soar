//go:build linux

package storagequota

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

type mount struct {
	point   string
	fsType  string
	options string
}

func decodeMountPath(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func dataMount(dataRoot string) (mount, error) {
	root, err := filepath.Abs(dataRoot)
	if err != nil {
		return mount{}, err
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return mount{}, err
	}
	defer file.Close()
	best := mount{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			continue
		}
		point := decodeMountPath(fields[4])
		if root != point && !strings.HasPrefix(root, strings.TrimRight(point, "/")+"/") {
			continue
		}
		if len(point) >= len(best.point) {
			best = mount{point: point, fsType: fields[separator+1], options: fields[5] + "," + fields[separator+3]}
		}
	}
	if err := scanner.Err(); err != nil {
		return mount{}, err
	}
	if best.point == "" {
		return mount{}, fmt.Errorf("storage quota: mount for %s not found", root)
	}
	return best, nil
}

func Detect(dataRoot string) Info {
	m, err := dataMount(dataRoot)
	if err != nil {
		return info("unknown", "error")
	}
	options := "," + m.options + ","
	if m.fsType != "xfs" || (!strings.Contains(options, ",prjquota,") && !strings.Contains(options, ",pquota,")) {
		return info("none", "unsupported")
	}
	if _, err := exec.LookPath("xfs_quota"); err != nil {
		return info("xfs_project", "error")
	}
	return info("xfs_project", "ready")
}

func projectID(root string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.Base(root)))
	return 10_000 + h.Sum32()%2_000_000_000
}

func safeCommandPath(value string) (string, error) {
	if strings.ContainsAny(value, ";'\"") || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("storage quota: unsupported path characters")
	}
	return value, nil
}

// Apply assigns the complete server data directory to an XFS project and
// enforces the byte limit at the filesystem layer. This also applies while
// the container is stopped and covers writes that bypass the Soar file API.
func Apply(dataRoot, serverRoot string, limitBytes int64) error {
	if limitBytes < 0 {
		return fmt.Errorf("storage quota: limit cannot be negative")
	}
	status := Detect(dataRoot)
	if status.Status != "ready" {
		return nil
	}
	data, err := filepath.Abs(dataRoot)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(serverRoot)
	if err != nil {
		return err
	}
	if root == data || !strings.HasPrefix(root, strings.TrimRight(data, string(os.PathSeparator))+string(os.PathSeparator)) {
		return fmt.Errorf("storage quota: server directory escapes data root")
	}
	safeRoot, err := safeCommandPath(root)
	if err != nil {
		return err
	}
	m, err := dataMount(data)
	if err != nil {
		return err
	}
	id := strconv.FormatUint(uint64(projectID(root)), 10)
	commands := []string{
		"project -s -p " + safeRoot + " " + id,
		"limit -p bsoft=" + strconv.FormatInt(limitBytes, 10) + " bhard=" + strconv.FormatInt(limitBytes, 10) + " " + id,
	}
	for _, command := range commands {
		output, err := exec.Command("xfs_quota", "-x", "-c", command, m.point).CombinedOutput()
		if err != nil {
			return fmt.Errorf("storage quota: xfs_quota failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}
