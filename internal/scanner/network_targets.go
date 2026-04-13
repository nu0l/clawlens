package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	remoteDialTimeout = 800 * time.Millisecond
	remoteHTTPTimeout = 1200 * time.Millisecond
	remoteWorkers     = 64
	progressEveryN    = 10
)

type TargetScanOptions struct {
	Workers       int
	DialTimeout   time.Duration
	HTTPTimeout   time.Duration
	ProgressEvery int
	Progress      func(done, total int)
}

// ScanTargetNetwork checks specified IP targets for OpenClaw gateway exposure and auth risks.
func ScanTargetNetwork(targets []string, dial dialFunc, client *http.Client, opts *TargetScanOptions) ([]Finding, error) {
	return scanTargetNetwork(targets, gatewayPort, dial, client, opts)
}

func scanTargetNetwork(targets []string, port int, dial dialFunc, client *http.Client, opts *TargetScanOptions) ([]Finding, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = &TargetScanOptions{}
	}
	if dial == nil {
		dial = net.DialTimeout
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = remoteDialTimeout
	}
	if opts.HTTPTimeout <= 0 {
		opts.HTTPTimeout = remoteHTTPTimeout
	}
	if opts.ProgressEvery <= 0 {
		opts.ProgressEvery = progressEveryN
	}
	if client == nil {
		client = &http.Client{Timeout: opts.HTTPTimeout}
	}

	workerCount := opts.Workers
	if workerCount <= 0 {
		workerCount = remoteWorkers
	}
	if len(targets) < workerCount {
		workerCount = len(targets)
	}

	jobs := make(chan string)
	results := make(chan Finding, len(targets))
	var wg sync.WaitGroup
	var doneCount int64

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if finding, ok := scanSingleTarget(target, port, dial, client, opts.DialTimeout); ok {
					results <- finding
				}
				if opts.Progress != nil {
					done := int(atomic.AddInt64(&doneCount, 1))
					if done == len(targets) || done%opts.ProgressEvery == 0 {
						opts.Progress(done, len(targets))
					}
				}
			}
		}()
	}

	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	findings := make([]Finding, 0)
	for finding := range results {
		findings = append(findings, finding)
	}

	return findings, nil
}

func scanSingleTarget(target string, port int, dial dialFunc, client *http.Client, dialTimeout time.Duration) (Finding, bool) {
	address := net.JoinHostPort(target, strconv.Itoa(port))
	conn, err := dial("tcp", address, dialTimeout)
	if err != nil {
		return Finding{}, false
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

	return finding, true
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
