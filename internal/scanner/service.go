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
				Title:       "OpenClaw service active",
				Description: "A registered OpenClaw system service is currently running.",
				Severity:    Warning,
				Details:     map[string]string{"name": svc.Name, "status": "active"},
			})
		} else {
			findings = append(findings, Finding{
				Category:    CatService,
				Title:       "OpenClaw service registered",
				Description: "A registered OpenClaw system service exists but is not running.",
				Severity:    Info,
				Details:     map[string]string{"name": svc.Name, "status": "inactive"},
			})
		}
	}

	return findings, nil
}
