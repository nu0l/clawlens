package scanner

import (
	"fmt"
	"net"
	"time"
)

const (
	gatewayPort    = 18789
	dialTimeout    = 2 * time.Second
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
		Title:       "Gateway port is open",
		Description: fmt.Sprintf("OpenClaw gateway is listening on port %d. The gateway exposes an HTTP API that may allow remote control of the agent.", gatewayPort),
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
		Title:       "Gateway exposed to network",
		Description: fmt.Sprintf("OpenClaw gateway port %d is reachable on all interfaces (0.0.0.0). This exposes the agent to the entire network.", gatewayPort),
		Severity:    Critical,
		Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "address": allAddr},
	})

	return findings, nil
}
