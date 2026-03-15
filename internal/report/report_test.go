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
				Title:       "Shell 访问已启用",
				Description: "危险配置",
				Severity:    scanner.Critical,
			},
		},
		Issues: []scanner.ScanIssue{
			{Check: "services", Error: "launchctl 不可用"},
		},
		MaxSeverity: scanner.Critical,
	}

	var output bytes.Buffer
	if err := WriteHTML(&output, result, "1.2.3"); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	rendered := output.String()
	for _, needle := range []string{
		"ClawLens 安全报告",
		"扫描异常",
		"launchctl 不可用",
		"配置检测",
		"Shell 访问已启用",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("rendered HTML missing %q", needle)
		}
	}
}
