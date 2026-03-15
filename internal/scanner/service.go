package scanner

import "github.com/clawlens/clawlens/internal/platform"

// ScanServices checks for registered OpenClaw system services.
func ScanServices(plat platform.Platform) ([]Finding, error) {
	var findings []Finding

	services, err := plat.FindServices()
	if err != nil {
		return findings, err
	}

	for _, svc := range services {
		if svc.Active {
			findings = append(findings, Finding{
				Category:    CatService,
				Title:       "OpenClaw 服务正在运行",
				Description: "已注册的 OpenClaw 系统服务当前处于运行状态。",
				Severity:    Warning,
				Details:     map[string]string{"name": svc.Name, "status": "active"},
			})
		} else {
			findings = append(findings, Finding{
				Category:    CatService,
				Title:       "OpenClaw 服务已注册",
				Description: "已注册的 OpenClaw 系统服务当前未运行。",
				Severity:    Info,
				Details:     map[string]string{"name": svc.Name, "status": "inactive"},
			})
		}
	}

	return findings, nil
}
