package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/clawlens/clawlens/internal/platform"
)

type fakePlatform struct{}

func (fakePlatform) OpenClawHome() string                           { return "/tmp/.openclaw" }
func (fakePlatform) FindProcesses() ([]platform.ProcessInfo, error) { return nil, nil }
func (fakePlatform) FindServices() ([]platform.ServiceInfo, error)  { return nil, nil }
func (fakePlatform) OpenBrowser(string) error                       { return nil }

func TestScannerRunCollectsIssuesAndSortsFindings(t *testing.T) {
	scan := newWithChecks(fakePlatform{}, "/tmp/openclaw",
		scanCheck{
			name: "filesystem",
			run: func(scanContext) ([]Finding, error) {
				return []Finding{{
					Category: CatInstallation,
					Title:    "Installation found",
					Severity: Info,
				}}, nil
			},
		},
		scanCheck{
			name: "processes",
			run: func(scanContext) ([]Finding, error) {
				return []Finding{{
					Category: CatProcess,
					Title:    "Gateway process running",
					Severity: Critical,
				}}, errors.New("ps unavailable")
			},
		},
	)

	scan.now = func() time.Time {
		return time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	}
	scan.hostname = func() (string, error) {
		return "test-host", nil
	}

	result := scan.Run()

	if got, want := result.Hostname, "test-host"; got != want {
		t.Fatalf("Hostname = %q, want %q", got, want)
	}
	if got, want := len(result.Issues), 1; got != want {
		t.Fatalf("len(Issues) = %d, want %d", got, want)
	}
	if got, want := result.Issues[0].Check, "processes"; got != want {
		t.Fatalf("Issues[0].Check = %q, want %q", got, want)
	}
	if got, want := result.MaxSeverity, Critical; got != want {
		t.Fatalf("MaxSeverity = %v, want %v", got, want)
	}
	if got, want := result.Findings[0].Title, "Gateway process running"; got != want {
		t.Fatalf("Findings[0].Title = %q, want %q", got, want)
	}
}

func TestScanConfigInvalidJSONCreatesWarningFinding(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "openclaw.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := ScanConfig(home)
	if err != nil {
		t.Fatalf("ScanConfig returned error: %v", err)
	}
	if got, want := len(findings), 1; got != want {
		t.Fatalf("len(findings) = %d, want %d", got, want)
	}
	if got, want := findings[0].Severity, Warning; got != want {
		t.Fatalf("findings[0].Severity = %v, want %v", got, want)
	}
	if got, want := findings[0].Title, "Configuration file could not be parsed"; got != want {
		t.Fatalf("findings[0].Title = %q, want %q", got, want)
	}
}
