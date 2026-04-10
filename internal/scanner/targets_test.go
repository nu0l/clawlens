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

	for _, want := range []string{"192.168.1.10", "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"} {
		if !slices.Contains(targets, want) {
			t.Fatalf("targets missing %s: %v", want, targets)
		}
	}
}

func TestParseTargetsRejectsInvalid(t *testing.T) {
	_, err := ParseTargets("not-an-ip")
	if err == nil {
		t.Fatal("ParseTargets should reject invalid target")
	}
}
