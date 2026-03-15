package scanner

import "github.com/clawlens/clawlens/internal/platform"

// ScanProcesses checks for running OpenClaw-related processes.
func ScanProcesses(plat platform.Platform) ([]Finding, error) {
	var findings []Finding

	procs, err := plat.FindProcesses()
	if err != nil {
		return findings, err
	}

	for _, proc := range procs {
		findings = append(findings, Finding{
			Category:    CatProcess,
			Title:       "OpenClaw 进程正在运行",
			Description: "检测到 OpenClaw 相关进程正在活跃运行。",
			Remediation: "如非授权运行，应立即终止该进程（kill PID）。排查进程启动来源，检查是否有计划任务或开机启动项自动拉起。",
			Severity:    Warning,
			Details: map[string]string{
				"pid":     proc.PID,
				"name":    proc.Name,
				"command": proc.Cmd,
			},
		})
	}

	return findings, nil
}
