package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ScanTargetNetwork checks specified IP targets for OpenClaw gateway exposure and auth risks.
func ScanTargetNetwork(targets []string, dial dialFunc, client *http.Client) ([]Finding, error) {
	return scanTargetNetwork(targets, gatewayPort, dial, client)
}

func scanTargetNetwork(targets []string, port int, dial dialFunc, client *http.Client) ([]Finding, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if dial == nil {
		dial = net.DialTimeout
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}

	findings := make([]Finding, 0)
	for _, target := range targets {
		address := net.JoinHostPort(target, strconv.Itoa(port))
		conn, err := dial("tcp", address, dialTimeout)
		if err != nil {
			continue
		}
		_ = conn.Close()

		finding := Finding{
			Category:    CatNetwork,
			Title:       "发现疑似 OpenClaw 网关",
			Description: fmt.Sprintf("目标 %s 的 %d 端口开放，疑似存在 OpenClaw 安装实例。", target, port),
			Remediation: "确认该主机是否为授权节点；仅允许受信网段访问，建议结合防火墙白名单与最小权限网络策略。",
			Severity:    Warning,
			Details: map[string]string{
				"target": target,
				"port":   fmt.Sprintf("%d", port),
			},
		}

		if authRisk := probeAuthRisk(client, target, port); authRisk != nil {
			finding.Severity = Critical
			finding.Title = "目标网关疑似未授权访问"
			finding.Description = fmt.Sprintf("目标 %s 的网关存在未授权访问风险。", target)
			finding.Remediation = "立即启用网关认证（Token/Password），并限制来源 IP；同时排查是否已有异常访问记录。"
			for k, v := range authRisk {
				finding.Details[k] = v
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func probeAuthRisk(client *http.Client, target string, port int) map[string]string {
	url := fmt.Sprintf("http://%s:%d/", target, port)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	content := strings.ToLower(string(body))
	server := strings.ToLower(resp.Header.Get("Server"))

	if resp.StatusCode < 400 || strings.Contains(content, "openclaw") || strings.Contains(server, "openclaw") {
		return map[string]string{
			"http_status": resp.Status,
			"probe":       "GET /",
		}
	}

	return nil
}
