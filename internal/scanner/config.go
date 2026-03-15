package scanner

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type openClawConfig struct {
	ShellAccess bool   `json:"shellAccess"`
	GatewayBind string `json:"gatewayBind"`
}

// ScanConfig parses the OpenClaw configuration and checks for risky settings.
func ScanConfig(homeDir string) ([]Finding, error) {
	var findings []Finding

	configPath := filepath.Join(homeDir, "openclaw.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return findings, nil
		}
		return findings, err
	}

	var config openClawConfig
	if err := json.Unmarshal(data, &config); err != nil {
		findings = append(findings, Finding{
			Category:    CatConfig,
			Title:       "Configuration file could not be parsed",
			Description: "OpenClaw configuration exists but could not be parsed. Risk evaluation may be incomplete.",
			Severity:    Warning,
			Details: map[string]string{
				"path":  configPath,
				"error": err.Error(),
			},
		})
		return findings, nil
	}

	// Check shell access
	if config.ShellAccess {
		findings = append(findings, Finding{
			Category:    CatConfig,
			Title:       "Shell access enabled",
			Description: "OpenClaw is configured with shell access enabled. This allows arbitrary command execution and is a critical security risk.",
			Severity:    Critical,
			Details:     map[string]string{"setting": "shellAccess", "value": "true"},
		})
	}

	// Check gateway bind address
	if bind := config.GatewayBind; strings.HasPrefix(bind, "0.0.0.0") || strings.HasPrefix(bind, "[::]") || strings.HasPrefix(bind, ":") {
		findings = append(findings, Finding{
			Category:    CatConfig,
			Title:       "Gateway bound to all interfaces",
			Description: "The OpenClaw gateway is configured to listen on every interface, exposing it to the network. This makes the instance reachable beyond localhost.",
			Severity:    Critical,
			Details:     map[string]string{"setting": "gatewayBind", "value": bind},
		})
	}

	return findings, nil
}
