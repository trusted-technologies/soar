package updater

import (
	"strings"
	"testing"
)

func TestExpectedChecksum(t *testing.T) {
	value := strings.Repeat("a", 64)
	checksum, err := ExpectedChecksum(strings.NewReader(value+"  soar_linux_amd64\n"), "soar_linux_amd64")
	if err != nil {
		t.Fatal(err)
	}
	if checksum != value {
		t.Fatalf("expected %s, got %s", value, checksum)
	}
}

func TestExpectedChecksumRejectsMissingAsset(t *testing.T) {
	if _, err := ExpectedChecksum(strings.NewReader(strings.Repeat("a", 64)+"  other\n"), "soar_linux_amd64"); err == nil {
		t.Fatal("expected missing checksum error")
	}
}
