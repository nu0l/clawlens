package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/clawlens/clawlens/internal/scanner"
)

func TestWriteHTMLIncludesGroupedFindingsAndIssues(t *testing.T) {
	result := &scanner.ScanResult{
		Hostname: "host-1",
		OS:       "linux",
		Arch:     "amd64",
		ScanTime: time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC),
		Findings: []scanner.Finding{
			{
				Category:    scanner.CatConfig,
				Title:       "Shell access enabled",
				Description: "dangerous",
				Severity:    scanner.Critical,
			},
		},
		Issues: []scanner.ScanIssue{
			{Check: "services", Error: "launchctl not available"},
		},
		MaxSeverity: scanner.Critical,
	}

	var output bytes.Buffer
	if err := WriteHTML(&output, result, "1.2.3"); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	rendered := output.String()
	for _, needle := range []string{
		"ClawLens Report",
		"Scan Issues",
		"launchctl not available",
		"Configuration",
		"Shell access enabled",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered HTML missing %q", needle)
		}
	}
}
