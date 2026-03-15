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
			Title:       "配置文件解析失败",
			Description: "OpenClaw 配置文件存在但无法解析，风险评估可能不完整。",
			Remediation: "检查配置文件格式是否正确（JSON 语法）。如文件已损坏，建议从备份恢复或重新生成配置。",
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
			Title:       "Shell 访问已启用",
			Description: "OpenClaw 配置了 Shell 访问权限，允许执行任意命令，存在严重安全风险。",
			Remediation: "立即在配置文件中将 shellAccess 设置为 false。如业务确需 Shell 功能，应通过白名单限制可执行的命令，并启用操作审计日志。",
			Severity:    Critical,
			Details:     map[string]string{"setting": "shellAccess", "value": "true"},
		})
	}

	// Check gateway bind address
	if bind := config.GatewayBind; strings.HasPrefix(bind, "0.0.0.0") || strings.HasPrefix(bind, "[::]") || strings.HasPrefix(bind, ":") {
		findings = append(findings, Finding{
			Category:    CatConfig,
			Title:       "网关绑定到所有网络接口",
			Description: "OpenClaw 网关配置为监听所有网络接口，使实例暴露在网络中，可从 localhost 以外访问。",
			Remediation: "将 gatewayBind 修改为 127.0.0.1 以仅允许本地访问。如需远程访问，应通过防火墙规则或 VPN 限制来源 IP，并启用身份认证。",
			Severity:    Critical,
			Details:     map[string]string{"setting": "gatewayBind", "value": bind},
		})
	}

	return findings, nil
}
