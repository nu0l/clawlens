package scanner

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/clawlens/clawlens/internal/platform"
)

type scanContext struct {
	Platform           platform.Platform
	HomeDir            string
	RemoteTargets      []string
	RemoteWorkers      int
	RemoteDialTimeout  time.Duration
	RemoteProgressStep int
	RemoteProgress     func(done, total int)
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
func New(
	plat platform.Platform,
	homeDir string,
	remoteTargets []string,
	remoteWorkers int,
	remoteDialTimeout time.Duration,
	remoteProgressStep int,
	runLocal bool,
	runRemote bool,
	remoteProgress func(done, total int),
) *Scanner {
	s := newWithChecks(plat, homeDir, defaultChecks(runLocal, runRemote)...)
	s.context.RemoteTargets = remoteTargets
	s.context.RemoteWorkers = remoteWorkers
	s.context.RemoteDialTimeout = remoteDialTimeout
	s.context.RemoteProgressStep = remoteProgressStep
	s.context.RemoteProgress = remoteProgress
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

func defaultChecks(runLocal bool, runRemote bool) []scanCheck {
	checks := make([]scanCheck, 0, 6)
	if runLocal {
		checks = append(checks,
			scanCheck{
				name: "filesystem",
				run: func(ctx scanContext) ([]Finding, error) {
					return ScanFilesystem(ctx.HomeDir)
				},
			},
			scanCheck{
				name: "processes",
				run: func(ctx scanContext) ([]Finding, error) {
					return ScanProcesses(ctx.Platform)
				},
			},
			scanCheck{
				name: "services",
				run: func(ctx scanContext) ([]Finding, error) {
					return ScanServices(ctx.Platform)
				},
			},
			scanCheck{
				name: "config",
				run: func(ctx scanContext) ([]Finding, error) {
					return ScanConfig(ctx.HomeDir)
				},
			},
			scanCheck{
				name: "credentials",
				run: func(ctx scanContext) ([]Finding, error) {
					return ScanCredentials(ctx.HomeDir)
				},
			},
		)
	}

	if runLocal || runRemote {
		checks = append(checks, scanCheck{
			name: "network",
			run: func(ctx scanContext) ([]Finding, error) {
				var localFindings []Finding
				var localErr error
				if runLocal {
					localFindings, localErr = ScanNetwork(nil)
				}

				var remoteFindings []Finding
				var remoteErr error
				if runRemote {
					remoteFindings, remoteErr = ScanTargetNetwork(ctx.RemoteTargets, nil, nil, &TargetScanOptions{
						Workers:       ctx.RemoteWorkers,
						DialTimeout:   ctx.RemoteDialTimeout,
						HTTPTimeout:   maxDuration(1200*time.Millisecond, ctx.RemoteDialTimeout*2),
						ProgressEvery: ctx.RemoteProgressStep,
						Progress:      ctx.RemoteProgress,
					})
				}

				findings := append(localFindings, remoteFindings...)
				if remoteErr != nil {
					if localErr != nil {
						return findings, fmt.Errorf("本地网络检测失败: %v；目标网络检测失败: %w", localErr, remoteErr)
					}
					return findings, fmt.Errorf("目标网络检测失败: %w", remoteErr)
				}
				if localErr != nil {
					return findings, fmt.Errorf("本地网络检测失败: %w", localErr)
				}

				return findings, nil
			},
		})
	}

	return checks
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
