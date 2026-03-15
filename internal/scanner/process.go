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
