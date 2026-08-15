package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pterodactyl/wings/system"
)

const (
	releaseAPI    = "https://api.github.com/repos/trusted-technologies/soar/releases/latest"
	maxBinarySize = 256 << 20
)

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type release struct {
	Tag    string  `json:"tag_name"`
	Assets []asset `json:"assets"`
}

type Result struct {
	Current string `json:"current"`
	Version string `json:"version"`
	Updated bool   `json:"updated"`
}

func normalizeVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}

func fetch(ctx context.Context, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "soar-updater")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, fmt.Errorf("release server returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return response, nil
}

func latest(ctx context.Context) (release, error) {
	response, err := fetch(ctx, releaseAPI)
	if err != nil {
		return release{}, err
	}
	defer response.Body.Close()
	var value release
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&value); err != nil {
		return release{}, err
	}
	if value.Tag == "" {
		return release{}, errors.New("release does not contain a version")
	}
	return value, nil
}

func assetURL(value release, name string) string {
	for _, item := range value.Assets {
		if item.Name == name {
			return item.URL
		}
	}
	return ""
}

func expectedChecksum(content io.Reader, binaryName string) (string, error) {
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && strings.TrimPrefix(fields[len(fields)-1], "*") == binaryName {
			value := strings.ToLower(fields[0])
			if len(value) != sha256.Size*2 {
				return "", errors.New("invalid checksum length")
			}
			if _, err := hex.DecodeString(value); err != nil {
				return "", errors.New("invalid checksum")
			}
			return value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("binary checksum is missing")
}

func downloadChecksum(ctx context.Context, url, binaryName string) (string, error) {
	response, err := fetch(ctx, url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	return expectedChecksum(io.LimitReader(response.Body, 1<<20), binaryName)
}

func downloadBinary(ctx context.Context, url, destination, expected string) error {
	response, err := fetch(ctx, url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxBinarySize+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > maxBinarySize {
		return errors.New("release binary is too large")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("release checksum mismatch: expected %s, got %s", expected, actual)
	}
	return os.Chmod(destination, 0o755)
}

func replaceExecutable(next string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	backup := executable + ".previous"
	_ = os.Remove(backup)
	if err := os.Rename(executable, backup); err != nil {
		return err
	}
	if err := os.Rename(next, executable); err != nil {
		_ = os.Rename(backup, executable)
		return err
	}
	return nil
}

func Update(ctx context.Context) (Result, error) {
	if runtime.GOOS != "linux" {
		return Result{}, errors.New("self-update is supported only on Linux nodes")
	}
	value, err := latest(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Current: normalizeVersion(system.Version), Version: normalizeVersion(value.Tag)}
	if result.Current == result.Version {
		return result, nil
	}
	binaryName := "soar_linux_" + runtime.GOARCH
	binaryURL := assetURL(value, binaryName)
	checksumsURL := assetURL(value, "SHA256SUMS")
	if binaryURL == "" || checksumsURL == "" {
		return Result{}, fmt.Errorf("release %s does not contain %s and SHA256SUMS", value.Tag, binaryName)
	}
	expected, err := downloadChecksum(ctx, checksumsURL, binaryName)
	if err != nil {
		return Result{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return Result{}, err
	}
	next, err := os.CreateTemp(filepath.Dir(executable), ".soar-update-*")
	if err != nil {
		return Result{}, err
	}
	nextPath := next.Name()
	if err := next.Close(); err != nil {
		return Result{}, err
	}
	if err := os.Remove(nextPath); err != nil {
		return Result{}, err
	}
	defer os.Remove(nextPath)
	if err := downloadBinary(ctx, binaryURL, nextPath, expected); err != nil {
		return Result{}, err
	}
	if err := replaceExecutable(nextPath); err != nil {
		return Result{}, err
	}
	result.Updated = true
	return result, nil
}

func RestartServiceAfter(delay time.Duration) {
	time.Sleep(delay)
	command := exec.Command("systemctl", "restart", "soar.service")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	_ = command.Start()
}

// ExpectedChecksum is exported for release-pipeline and parser tests.
func ExpectedChecksum(content io.Reader, binaryName string) (string, error) {
	return expectedChecksum(content, binaryName)
}
