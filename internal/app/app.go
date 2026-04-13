package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	output        string
	format        report.Format
	noOpen        bool
	openclawHome  string
	targets       []string
	workers       int
	targetTimeout time.Duration
	progressEvery int
	quiet         bool
	showVersion   bool
}

func Run(args []string, stdout, stderr io.Writer, cfg Config) int {
	initConsole()

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

	color := colorEnabled()
	plat := platform.New()
	var progressMu sync.Mutex
	lastProgressWidth := 0
	interactiveProgress := false
	if file, ok := stdout.(*os.File); ok {
		interactiveProgress = isTerminal(file)
	}
	progress := func(done, total int) {
		if opts.quiet {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		percent := float64(done) / float64(total) * 100
		line := fmt.Sprintf("%s 内网扫描进度: %d/%d (%.0f%%)",
			colorize("提示:", colorCyan, color), done, total, percent)
		if interactiveProgress {
			padding := ""
			if lastProgressWidth > len(line) {
				padding = strings.Repeat(" ", lastProgressWidth-len(line))
			}
			fmt.Fprintf(stdout, "\r%s%s", line, padding)
			lastProgressWidth = len(line)
			return
		}
		fmt.Fprintln(stdout, line)
	}
	scan := scanner.New(
		plat,
		opts.openclawHome,
		opts.targets,
		opts.workers,
		opts.targetTimeout,
		opts.progressEvery,
		progress,
	)

	if !opts.quiet {
		title := fmt.Sprintf("ClawLens %s", cfg.Version)
		fmt.Fprintf(stdout, "%s -- OpenClaw 安全扫描器\n\n",
			colorize(title, colorBoldCyan, color))
		fmt.Fprintln(stdout, colorize("正在扫描...", colorGray, color))
		if len(opts.targets) > 0 {
			fmt.Fprintf(stdout, "%s 内网目标扫描已启用：%d 个目标（并发探测）\n",
				colorize("提示:", colorCyan, color), len(opts.targets))
		}
	}
	scanStart := time.Now()
	result := scan.Run()

	if !opts.quiet && len(opts.targets) > 0 {
		progressMu.Lock()
		if interactiveProgress && lastProgressWidth > 0 {
			fmt.Fprintln(stdout)
		}
		progressMu.Unlock()
		fmt.Fprintf(stdout, "%s 内网目标扫描完成，耗时 %s\n",
			colorize("提示:", colorCyan, color), time.Since(scanStart).Round(time.Millisecond))
		printTargetScanSummary(stdout, result, len(opts.targets), color)
	}

	if !opts.quiet {
		printFindings(stdout, result, color)
		printIssues(stderr, result, color)
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
		fmt.Fprintf(stdout, "\n%s %s\n",
			colorize("报告已保存至", colorGray, color),
			colorize(outputPath, colorBoldWhite, color))
	}

	if opts.shouldOpenBrowser() {
		if !hasDesktopEnvironment() {
			if !opts.quiet {
				fmt.Fprintf(stderr, "%s 未检测到桌面环境，跳过浏览器打开。\n",
					colorize("提示:", colorCyan, color))
				fmt.Fprintf(stderr, "      请将报告文件复制到有浏览器的机器上查看。\n")
			}
		} else if err := openReportInBrowser(plat, outputPath); err != nil && !opts.quiet {
			fmt.Fprintf(stderr, "警告: 无法打开浏览器: %v\n", err)
		}
	}

	return int(result.MaxSeverity)
}

type targetScanSummary struct {
	TotalTargets    int
	DiscoveredHosts []string
	CriticalHosts   []string
}

func summarizeTargetScan(result *scanner.ScanResult, totalTargets int) targetScanSummary {
	summary := targetScanSummary{TotalTargets: totalTargets}
	discovered := make(map[string]struct{})
	critical := make(map[string]struct{})

	for _, finding := range result.Findings {
		target, ok := finding.Details["target"]
		if !ok || strings.TrimSpace(target) == "" {
			continue
		}
		discovered[target] = struct{}{}
		if finding.Severity == scanner.Critical {
			critical[target] = struct{}{}
		}
	}

	for host := range discovered {
		summary.DiscoveredHosts = append(summary.DiscoveredHosts, host)
	}
	for host := range critical {
		summary.CriticalHosts = append(summary.CriticalHosts, host)
	}

	slices.Sort(summary.DiscoveredHosts)
	slices.Sort(summary.CriticalHosts)
	return summary
}

func printTargetScanSummary(w io.Writer, result *scanner.ScanResult, totalTargets int, color bool) {
	summary := summarizeTargetScan(result, totalTargets)
	fmt.Fprintf(w, "%s 扫描目标总数: %d，发现主机: %d，高危主机: %d\n",
		colorize("统计:", colorCyan, color),
		summary.TotalTargets,
		len(summary.DiscoveredHosts),
		len(summary.CriticalHosts),
	)

	if len(summary.DiscoveredHosts) == 0 {
		fmt.Fprintf(w, "%s 本次未发现内网 OpenClaw 网关暴露主机。\n", colorize("统计:", colorCyan, color))
		return
	}

	fmt.Fprintf(w, "%s 发现主机 IP: %s\n",
		colorize("统计:", colorCyan, color), strings.Join(summary.DiscoveredHosts, ", "))
	if len(summary.CriticalHosts) > 0 {
		fmt.Fprintf(w, "%s 高危主机 IP: %s\n",
			colorize("统计:", colorCyan, color), strings.Join(summary.CriticalHosts, ", "))
	}
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
	var targetSpec string
	fs.StringVar(&targetSpec, "targets", "", "指定扫描目标 IP/网段，支持逗号分隔（如 192.168.1.10,192.168.1.0/24）")
	fs.IntVar(&opts.workers, "workers", 64, "内网目标扫描并发数")
	fs.DurationVar(&opts.targetTimeout, "target-timeout", 800*time.Millisecond, "内网目标连接超时时间（如 800ms, 2s）")
	fs.IntVar(&opts.progressEvery, "progress-every", 10, "每处理 N 个目标输出一次实时进度")
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

	targets, err := scanner.ParseTargets(targetSpec)
	if err != nil {
		return opts, err
	}
	opts.targets = targets
	if opts.workers <= 0 {
		return opts, fmt.Errorf("workers 必须大于 0")
	}
	if opts.targetTimeout <= 0 {
		return opts, fmt.Errorf("target-timeout 必须大于 0")
	}
	if opts.progressEvery <= 0 {
		return opts, fmt.Errorf("progress-every 必须大于 0")
	}

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

const separator = "────────────────────────────────────────"

func printFindings(w io.Writer, result *scanner.ScanResult, color bool) {
	if len(result.Findings) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, colorize("  [安全] 未检测到 OpenClaw 安装。", colorBoldGreen, color))
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w)
	for _, finding := range result.Findings {
		icon, tagColor := severityStyle(finding.Severity)
		tag := colorize(fmt.Sprintf(" %s ", finding.Severity), tagColor, color)
		fmt.Fprintf(w, "  %s %s  %s\n", icon, tag, finding.Title)
		fmt.Fprintf(w, "      %s\n", colorize(finding.Description, colorGray, color))
		for k, v := range finding.Details {
			fmt.Fprintf(w, "      %s %s\n",
				colorize(k+":", colorCyan, color),
				v)
		}
		if finding.Remediation != "" {
			fmt.Fprintf(w, "      %s %s\n",
				colorize("治理:", colorBoldGreen, color),
				finding.Remediation)
		}
		fmt.Fprintln(w)
	}

	counts := result.CountBySeverity()
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(separator, colorGray, color))

	critical := colorize(fmt.Sprintf("%d 严重", counts[scanner.Critical]), colorBoldRed, color)
	warning := colorize(fmt.Sprintf("%d 警告", counts[scanner.Warning]), colorBoldYellow, color)
	info := colorize(fmt.Sprintf("%d 提示", counts[scanner.Info]), colorBoldBlue, color)
	fmt.Fprintf(w, "  扫描结果:  %s  %s  %s\n", critical, warning, info)

	fmt.Fprintln(w, colorize(separator, colorGray, color))
}

func printIssues(w io.Writer, result *scanner.ScanResult, color bool) {
	if len(result.Issues) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize("扫描异常:", colorYellow, color))
	for _, issue := range result.Issues {
		fmt.Fprintf(w, "  %s %s: %s\n",
			colorize("-", colorYellow, color),
			colorize(issue.Check, colorBoldYellow, color),
			issue.Error)
	}
	fmt.Fprintln(w)
}

// hasDesktopEnvironment checks whether a graphical desktop is available.
func hasDesktopEnvironment() bool {
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return true
	}
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv("OS")), "Windows_NT") ||
		os.Getenv("TERM_PROGRAM") != ""
}

func severityStyle(severity scanner.Severity) (icon string, tagColor string) {
	switch severity {
	case scanner.Critical:
		return "\033[31m●\033[0m", colorBoldRed
	case scanner.Warning:
		return "\033[33m▲\033[0m", colorBoldYellow
	case scanner.Info:
		return "\033[34m■\033[0m", colorBoldBlue
	default:
		return "\033[32m✔\033[0m", colorBoldGreen
	}
}
