package scanner

import (
	"fmt"
	"net"
	"time"
)

const (
	gatewayPort = 18789
	dialTimeout = 2 * time.Second
)

// dialFunc abstracts net.DialTimeout for testing.
type dialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

// ScanNetwork checks whether the OpenClaw gateway port is listening.
func ScanNetwork(dial dialFunc) ([]Finding, error) {
	if dial == nil {
		dial = net.DialTimeout
	}
	return scanGatewayPort(dial)
}

func scanGatewayPort(dial dialFunc) ([]Finding, error) {
	var findings []Finding
	addr := fmt.Sprintf("127.0.0.1:%d", gatewayPort)

	conn, err := dial("tcp", addr, dialTimeout)
	if err != nil {
		// Port not open — no finding
		return findings, nil
	}
	conn.Close()

	findings = append(findings, Finding{
		Category:    CatNetwork,
		Title:       "网关端口已开放",
		Description: fmt.Sprintf("OpenClaw 网关正在监听端口 %d，该端口暴露了 HTTP API，可能允许远程控制 Agent。", gatewayPort),
		Remediation: fmt.Sprintf("如非必要，关闭网关服务或通过防火墙封锁端口 %d。如需保留，确保仅绑定 127.0.0.1 并启用访问认证。", gatewayPort),
		Severity:    Warning,
		Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "address": addr},
	})

	// Check if also listening on all interfaces (network-exposed)
	allAddr := fmt.Sprintf("0.0.0.0:%d", gatewayPort)
	conn, err = dial("tcp", allAddr, dialTimeout)
	if err != nil {
		return findings, nil
	}
	conn.Close()

	findings = append(findings, Finding{
		Category:    CatNetwork,
		Title:       "网关暴露到外部网络",
		Description: fmt.Sprintf("OpenClaw 网关端口 %d 在所有网络接口 (0.0.0.0) 上可达，已暴露到整个网络。", gatewayPort),
		Remediation: "立即将网关绑定地址修改为 127.0.0.1，或通过 iptables/firewalld 限制入站流量。检查是否已有未授权的外部连接，并审计访问日志。",
		Severity:    Critical,
		Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "address": allAddr},
	})

	return findings, nil
}
