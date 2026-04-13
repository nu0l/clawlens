package scanner

import (
	"slices"
	"testing"
)

func TestParseTargetsIPAndCIDR(t *testing.T) {
	targets, err := ParseTargets("192.168.1.10, 192.168.1.0/30")
	if err != nil {
		t.Fatalf("ParseTargets returned error: %v", err)
	}

	for _, want := range []string{"192.168.1.10", "192.168.1.1", "192.168.1.2"} {
		if !slices.Contains(targets, want) {
			t.Fatalf("targets missing %s: %v", want, targets)
		}
	}
	if slices.Contains(targets, "192.168.1.0") || slices.Contains(targets, "192.168.1.3") {
		t.Fatalf("network/broadcast addresses should be excluded: %v", targets)
	}
}

func TestParseTargetsRejectsInvalid(t *testing.T) {
	_, err := ParseTargets("not-an-ip")
	if err == nil {
		t.Fatal("ParseTargets should reject invalid target")
	}
}

func TestParseTargetsAllowsSlash16(t *testing.T) {
	targets, err := ParseTargets("192.168.116.79/16")
	if err != nil {
		t.Fatalf("ParseTargets returned error: %v", err)
	}
	if len(targets) != 65534 {
		t.Fatalf("expected 65534 hosts for /16, got %d", len(targets))
	}
}
