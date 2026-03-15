package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// ScanFilesystem checks for OpenClaw installation artifacts on the filesystem.
func ScanFilesystem(homeDir string) ([]Finding, error) {
	var findings []Finding

	// Check main directory
	if info, err := os.Stat(homeDir); err == nil && info.IsDir() {
		findings = append(findings, Finding{
			Category:    CatInstallation,
			Title:       "检测到 OpenClaw 安装",
			Description: "OpenClaw 主目录已存在。",
			Remediation: "如非授权安装，请删除该目录并审查安装来源。如为合法使用，请确保版本为最新并定期审计配置。",
			Severity:    Info,
			Details:     map[string]string{"path": homeDir},
		})
	} else {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return findings, err
		}
		return findings, nil // No installation found, skip remaining checks
	}

	// Check config file
	configPath := filepath.Join(homeDir, "openclaw.json")
	if _, err := os.Stat(configPath); err == nil {
		findings = append(findings, Finding{
			Category:    CatInstallation,
			Title:       "发现配置文件",
			Description: "OpenClaw 配置文件已存在。",
			Remediation: "检查配置文件内容，确保未开启危险选项（如 Shell 访问、外部网络绑定）。建议将配置纳入变更管理。",
			Severity:    Info,
			Details:     map[string]string{"path": configPath},
		})
	}

	// Check workspace directory
	workspacePath := filepath.Join(homeDir, "workspace")
	if info, err := os.Stat(workspacePath); err == nil && info.IsDir() {
		findings = append(findings, Finding{
			Category:    CatInstallation,
			Title:       "发现工作区目录",
			Description: "OpenClaw 工作区目录已存在。",
			Remediation: "审查工作区中的文件内容，确认无敏感数据泄露。如不再使用，建议清理该目录。",
			Severity:    Info,
			Details:     map[string]string{"path": workspacePath},
		})
	}

	// Check agent sessions
	agentsPath := filepath.Join(homeDir, "agents")
	if info, err := os.Stat(agentsPath); err == nil && info.IsDir() {
		matches, _ := filepath.Glob(filepath.Join(agentsPath, "*/sessions"))
		if len(matches) > 0 {
			findings = append(findings, Finding{
				Category:    CatInstallation,
				Title:       "发现 Agent 会话",
				Description: "存在活跃或历史的 Agent 会话目录。",
				Remediation: "审查各 Agent 会话记录，确认无异常操作。定期清理历史会话，避免敏感信息残留。",
				Severity:    Info,
				Details:     map[string]string{"count": strconv.Itoa(len(matches)), "path": agentsPath},
			})
		}
	}

	// Check plugin artifacts
	pluginIndicators := []string{
		filepath.Join(homeDir, "index.js"),
		filepath.Join(homeDir, "plugin-sdk"),
	}
	for _, path := range pluginIndicators {
		if _, err := os.Stat(path); err == nil {
			findings = append(findings, Finding{
				Category:    CatInstallation,
				Title:       "检测到插件文件",
				Description: "发现插件相关文件，可能来自未经信任的 ClawHub 源。",
				Remediation: "审查插件来源和内容，仅保留可信的插件。删除未知或不必要的插件文件，并限制插件安装权限。",
				Severity:    Warning,
				Details:     map[string]string{"path": path},
			})
			break
		}
	}

	return findings, nil
}
