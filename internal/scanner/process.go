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
			Title:       "OpenClaw process running",
			Description: "An OpenClaw-related process is currently active.",
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
