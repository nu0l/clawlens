package app

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/clawlens/clawlens/internal/report"
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
	if len(opts.targets) != 5 {
		t.Fatalf("expected 5 targets, got %d", len(opts.targets))
	}
}
