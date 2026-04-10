package scanner

import (
	"os"
	"runtime"
	"time"

	"github.com/clawlens/clawlens/internal/platform"
)

type scanContext struct {
	Platform      platform.Platform
	HomeDir       string
	RemoteTargets []string
}

type scanCheck struct {
	name string
	run  func(scanContext) ([]Finding, error)
}

// Scanner orchestrates all detection checks.
type Scanner struct {
	context  scanContext
	checks   []scanCheck
	now      func() time.Time
	hostname func() (string, error)
}

// New creates a scanner. If homeDir is empty, it uses the platform default
// or the OPENCLAW_HOME environment variable.
func New(plat platform.Platform, homeDir string, remoteTargets []string) *Scanner {
	s := newWithChecks(plat, homeDir, defaultChecks()...)
	s.context.RemoteTargets = remoteTargets
	return s
}

func newWithChecks(plat platform.Platform, homeDir string, checks ...scanCheck) *Scanner {
	if homeDir == "" {
		if env := os.Getenv("OPENCLAW_HOME"); env != "" {
			homeDir = env
		} else {
			homeDir = plat.OpenClawHome()
		}
	}

	return &Scanner{
		context: scanContext{
			Platform: plat,
			HomeDir:  homeDir,
		},
		checks:   checks,
		now:      time.Now,
		hostname: os.Hostname,
	}
}

// Run executes all detection checks and returns the aggregated result.
func (s *Scanner) Run() *ScanResult {
	hostname, err := s.hostname()
	if err != nil {
		hostname = "unknown"
	}

	result := &ScanResult{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		ScanTime: s.now(),
	}

	for _, check := range s.checks {
		findings, err := check.run(s.context)
		if err != nil {
			result.AddIssue(check.name, err)
		}
		result.AddFindings(findings)
	}

	result.Finalize()
	return result
}

func defaultChecks() []scanCheck {
	return []scanCheck{
		{
			name: "filesystem",
			run: func(ctx scanContext) ([]Finding, error) {
				return ScanFilesystem(ctx.HomeDir)
			},
		},
		{
			name: "processes",
			run: func(ctx scanContext) ([]Finding, error) {
				return ScanProcesses(ctx.Platform)
			},
		},
		{
			name: "services",
			run: func(ctx scanContext) ([]Finding, error) {
				return ScanServices(ctx.Platform)
			},
		},
		{
			name: "config",
			run: func(ctx scanContext) ([]Finding, error) {
				return ScanConfig(ctx.HomeDir)
			},
		},
		{
			name: "credentials",
			run: func(ctx scanContext) ([]Finding, error) {
				return ScanCredentials(ctx.HomeDir)
			},
		},
		{
			name: "network",
			run: func(ctx scanContext) ([]Finding, error) {
				findings, err := ScanNetwork(nil)
				if err != nil {
					return nil, err
				}
				remoteFindings, err := ScanTargetNetwork(ctx.RemoteTargets, nil, nil)
				if err != nil {
					return nil, err
				}
				return append(findings, remoteFindings...), nil
			},
		},
	}
}
