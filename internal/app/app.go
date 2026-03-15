package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clawlens/clawlens/internal/browser"
	"github.com/clawlens/clawlens/internal/platform"
	"github.com/clawlens/clawlens/internal/report"
	"github.com/clawlens/clawlens/internal/scanner"
)

type Config struct {
	Version string
	Commit  string
}

type options struct {
	output       string
	format       report.Format
	noOpen       bool
	openclawHome string
	quiet        bool
	showVersion  bool
}

func Run(args []string, stdout, stderr io.Writer, cfg Config) int {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if opts.showVersion {
		fmt.Fprintf(stdout, "ClawLens %s (%s)\n", cfg.Version, cfg.Commit)
		return 0
	}

	plat := platform.New()
	scan := scanner.New(plat, opts.openclawHome)

	if !opts.quiet {
		fmt.Fprintf(stdout, "ClawLens %s -- OpenClaw Security Scanner\n\n", cfg.Version)
		fmt.Fprintln(stdout, "Scanning...")
	}

	result := scan.Run()

	if !opts.quiet {
		printFindings(stdout, result)
		printIssues(stderr, result)
	}

	if !opts.shouldWriteReport() {
		return int(result.MaxSeverity)
	}

	outputPath := opts.output
	if outputPath == "" {
		outputPath = defaultOutputPath(opts.format, time.Now())
	}

	if err := writeReport(outputPath, opts.format, result, cfg.Version); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if !opts.quiet {
		fmt.Fprintf(stdout, "Report saved to %s\n", outputPath)
	}

	if opts.shouldOpenBrowser() {
		if err := openReportInBrowser(plat, outputPath); err != nil && !opts.quiet {
			fmt.Fprintf(stderr, "Warning: could not open browser: %v\n", err)
		}
	}

	return int(result.MaxSeverity)
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var (
		opts      options
		formatRaw string
	)

	fs := flag.NewFlagSet("clawlens", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.output, "o", "", "report output path")
	fs.StringVar(&opts.output, "output", "", "report output path")
	fs.StringVar(&formatRaw, "f", string(report.FormatHTML), "output format: html, json")
	fs.StringVar(&formatRaw, "format", string(report.FormatHTML), "output format: html, json")
	fs.BoolVar(&opts.noOpen, "no-open", false, "don't auto-open browser")
	fs.StringVar(&opts.openclawHome, "openclaw-home", "", "specify OpenClaw directory")
	fs.BoolVar(&opts.quiet, "q", false, "quiet mode, exit code only")
	fs.BoolVar(&opts.quiet, "quiet", false, "quiet mode, exit code only")
	fs.BoolVar(&opts.showVersion, "v", false, "print version")
	fs.BoolVar(&opts.showVersion, "version", false, "print version")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	format, err := report.ParseFormat(formatRaw)
	if err != nil {
		return opts, err
	}
	opts.format = format

	return opts, nil
}

func (o options) shouldWriteReport() bool {
	return !o.quiet || o.output != ""
}

func (o options) shouldOpenBrowser() bool {
	return !o.quiet && !o.noOpen && o.format == report.FormatHTML
}

func defaultOutputPath(format report.Format, now time.Time) string {
	return filepath.Join(
		os.TempDir(),
		fmt.Sprintf("clawlens-report-%s.%s", now.Format("20060102-150405"), format),
	)
}

func writeReport(path string, format report.Format, result *scanner.ScanResult, version string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer file.Close()

	if err := report.Write(file, format, result, version); err != nil {
		return fmt.Errorf("writing %s report: %w", format, err)
	}

	return nil
}

func openReportInBrowser(plat platform.Platform, path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	reportURL := &url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(absPath),
	}
	return browser.Open(plat, reportURL.String())
}

func printFindings(w io.Writer, result *scanner.ScanResult) {
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "  [CLEAN] No OpenClaw installation detected.")
		fmt.Fprintln(w)
		return
	}

	for _, finding := range result.Findings {
		fmt.Fprintf(w, "%s %s\n", severityPrefix(finding.Severity), finding.Title)
	}

	counts := result.CountBySeverity()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %d critical, %d warnings, %d info\n",
		counts[scanner.Critical], counts[scanner.Warning], counts[scanner.Info])
}

func printIssues(w io.Writer, result *scanner.ScanResult) {
	if len(result.Issues) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Scan issues:")
	for _, issue := range result.Issues {
		fmt.Fprintf(w, "  - %s: %s\n", issue.Check, issue.Error)
	}
	fmt.Fprintln(w)
}

func severityPrefix(severity scanner.Severity) string {
	switch severity {
	case scanner.Critical:
		return "  [CRITICAL]"
	case scanner.Warning:
		return "  [WARNING] "
	case scanner.Info:
		return "  [INFO]    "
	default:
		return "  [CLEAN]   "
	}
}
