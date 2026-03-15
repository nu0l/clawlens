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
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	if opts.showVersion {
		fmt.Fprintf(stdout, "ClawLens %s (%s)\n", cfg.Version, cfg.Commit)
		return 0
	}

	plat := platform.New()
	scan := scanner.New(plat, opts.openclawHome)

	if !opts.quiet {
		fmt.Fprintf(stdout, "ClawLens %s -- OpenClaw 安全扫描器\n\n", cfg.Version)
		fmt.Fprintln(stdout, "正在扫描...")
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
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	if !opts.quiet {
		fmt.Fprintf(stdout, "报告已保存至 %s\n", outputPath)
	}

	if opts.shouldOpenBrowser() {
		if !hasDesktopEnvironment() {
			if !opts.quiet {
				fmt.Fprintf(stderr, "提示: 未检测到桌面环境，跳过浏览器打开。\n")
				fmt.Fprintf(stderr, "     请将报告文件 %s 复制到有浏览器的机器上查看。\n", outputPath)
			}
		} else if err := openReportInBrowser(plat, outputPath); err != nil && !opts.quiet {
			fmt.Fprintf(stderr, "警告: 无法打开浏览器: %v\n", err)
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
	fs.StringVar(&opts.output, "o", "", "报告输出路径")
	fs.StringVar(&opts.output, "output", "", "报告输出路径")
	fs.StringVar(&formatRaw, "f", string(report.FormatHTML), "输出格式: html, json")
	fs.StringVar(&formatRaw, "format", string(report.FormatHTML), "输出格式: html, json")
	fs.BoolVar(&opts.noOpen, "no-open", false, "不自动打开浏览器")
	fs.StringVar(&opts.openclawHome, "openclaw-home", "", "指定 OpenClaw 目录")
	fs.BoolVar(&opts.quiet, "q", false, "静默模式，仅返回退出码")
	fs.BoolVar(&opts.quiet, "quiet", false, "静默模式，仅返回退出码")
	fs.BoolVar(&opts.showVersion, "v", false, "显示版本号")
	fs.BoolVar(&opts.showVersion, "version", false, "显示版本号")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("意外的参数: %s", strings.Join(fs.Args(), " "))
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
		return fmt.Errorf("创建报告文件失败: %w", err)
	}
	defer file.Close()

	if err := report.Write(file, format, result, version); err != nil {
		return fmt.Errorf("写入 %s 报告失败: %w", format, err)
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
		fmt.Fprintln(w, "  [安全] 未检测到 OpenClaw 安装。")
		fmt.Fprintln(w)
		return
	}

	for _, finding := range result.Findings {
		fmt.Fprintf(w, "%s %s\n", severityPrefix(finding.Severity), finding.Title)
	}

	counts := result.CountBySeverity()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "扫描结果: %d 严重, %d 警告, %d 提示\n",
		counts[scanner.Critical], counts[scanner.Warning], counts[scanner.Info])
}

func printIssues(w io.Writer, result *scanner.ScanResult) {
	if len(result.Issues) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "扫描异常:")
	for _, issue := range result.Issues {
		fmt.Fprintf(w, "  - %s: %s\n", issue.Check, issue.Error)
	}
	fmt.Fprintln(w)
}

// hasDesktopEnvironment checks whether a graphical desktop is available.
// On Linux/macOS it looks for DISPLAY or WAYLAND_DISPLAY; on Windows a
// desktop is assumed to always exist.
func hasDesktopEnvironment() bool {
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return true
	}
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv("OS")), "Windows_NT") ||
		os.Getenv("TERM_PROGRAM") != ""
}

func severityPrefix(severity scanner.Severity) string {
	switch severity {
	case scanner.Critical:
		return "  [严重]"
	case scanner.Warning:
		return "  [警告]"
	case scanner.Info:
		return "  [提示]"
	default:
		return "  [安全]"
	}
}
