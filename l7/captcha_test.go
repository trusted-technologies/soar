package l7

import (
	"regexp"
	"testing"
)

func TestCaptchaIssueUsesEightCharacterRoutableCode(t *testing.T) {
	store := newCaptchaStore()
	code := store.issue("e6980591-ef2b-053b-0000-000000000000", "server", "192.0.2.1")

	if len(code) != 8 {
		t.Fatalf("expected an 8-character code, got %q", code)
	}
	if code[:2] != "e6" {
		t.Fatalf("expected node prefix e6, got %q", code[:2])
	}
	if !regexp.MustCompile(`^[a-z0-9_-]{2}[A-Za-z0-9_-]{6}$`).MatchString(code) {
		t.Fatalf("code is not URL-safe: %q", code)
	}

	uuid, ip, ok := store.resolve(code)
	if !ok || uuid != "server" || ip != "192.0.2.1" {
		t.Fatalf("issued code did not resolve: uuid=%q ip=%q ok=%v", uuid, ip, ok)
	}
	if _, _, ok := store.resolve(code); ok {
		t.Fatal("captcha code was not single-use")
	}
}

func TestCaptchaNodePrefixHandlesShortIDs(t *testing.T) {
	for input, expected := range map[string]string{
		"AB-CD": "ab",
		"x":     "x0",
		"":      "00",
	} {
		if got := captchaNodePrefix(input); got != expected {
			t.Fatalf("captchaNodePrefix(%q) = %q, expected %q", input, got, expected)
		}
	}
}
