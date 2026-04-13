package app

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/clawlens/clawlens/internal/report"
	"github.com/clawlens/clawlens/internal/scanner"
)

func TestParseOptionsRejectsInvalidFormat(t *testing.T) {
	_, err := parseOptions([]string{"-f", "xml"}, io.Discard)
	if err == nil {
		t.Fatal("parseOptions should reject unsupported formats")
	}
	if !strings.Contains(err.Error(), "不支持的格式") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQuietModeWithoutExplicitOutputSkipsReport(t *testing.T) {
	opts := options{quiet: true}
	if opts.shouldWriteReport() {
		t.Fatal("quiet mode without output should not write a report")
	}

	opts.output = "report.html"
	if !opts.shouldWriteReport() {
		t.Fatal("explicit output path should still write a report")
	}
}

func TestDefaultOutputPathUsesFormatExtension(t *testing.T) {
	now := time.Date(2026, 3, 15, 8, 4, 5, 0, time.UTC)
	path := defaultOutputPath(report.FormatJSON, now)
	if !strings.HasSuffix(path, "clawlens-report-20260315-080405.json") {
		t.Fatalf("unexpected output path: %s", path)
	}
}

func TestParseOptionsParsesTargets(t *testing.T) {
	opts, err := parseOptions([]string{"--targets", "192.168.1.10,192.168.1.0/30"}, io.Discard)
	if err != nil {
		t.Fatalf("parseOptions returned error: %v", err)
	}
	if len(opts.targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(opts.targets))
	}
}

func TestSummarizeTargetScan(t *testing.T) {
	result := &scanner.ScanResult{Findings: []scanner.Finding{
		{Severity: scanner.Warning, Details: map[string]string{"target": "172.31.0.10"}},
		{Severity: scanner.Critical, Details: map[string]string{"target": "172.31.0.20"}},
		{Severity: scanner.Critical, Details: map[string]string{"target": "172.31.0.20"}},
		{Severity: scanner.Info, Details: map[string]string{"path": "/tmp/no-target"}},
	}}

	summary := summarizeTargetScan(result, 254)
	if summary.TotalTargets != 254 {
		t.Fatalf("expected TotalTargets 254, got %d", summary.TotalTargets)
	}
	if len(summary.DiscoveredHosts) != 2 {
		t.Fatalf("expected 2 discovered hosts, got %d", len(summary.DiscoveredHosts))
	}
	if len(summary.CriticalHosts) != 1 || summary.CriticalHosts[0] != "172.31.0.20" {
		t.Fatalf("unexpected critical hosts: %v", summary.CriticalHosts)
	}
}

func TestParseOptionsRejectsInvalidWorkers(t *testing.T) {
	_, err := parseOptions([]string{"--workers", "0"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "workers") {
		t.Fatalf("expected workers validation error, got %v", err)
	}
}
