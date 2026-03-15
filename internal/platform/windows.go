//go:build windows

package platform

import (
	"encoding/csv"
	"io"
	"os/exec"
	"strings"
)

type windowsPlatform struct{}

func New() Platform {
	return &windowsPlatform{}
}

func (p *windowsPlatform) OpenClawHome() string {
	return defaultOpenClawHome()
}

func (p *windowsPlatform) FindProcesses() ([]ProcessInfo, error) {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, err
	}

	var procs []ProcessInfo
	reader := csv.NewReader(strings.NewReader(string(out)))
	reader.FieldsPerRecord = -1

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) < 2 {
			continue
		}

		name := record[0]
		if !isOpenClawCommand(name) {
			continue
		}

		procs = append(procs, ProcessInfo{
			PID:  record[1],
			Name: name,
			Cmd:  name,
		})
	}
	return procs, nil
}

func (p *windowsPlatform) FindServices() ([]ServiceInfo, error) {
	var services []ServiceInfo

	serviceNames := []string{"OpenClaw", "OpenClawGateway"}
	for _, name := range serviceNames {
		out, err := exec.Command("sc", "query", name).Output()
		if err != nil {
			continue
		}
		output := string(out)
		if strings.Contains(output, name) {
			active := strings.Contains(output, "RUNNING")
			services = append(services, ServiceInfo{Name: name, Active: active})
		}
	}
	return services, nil
}

func (p *windowsPlatform) OpenBrowser(url string) error {
	return exec.Command("cmd", "/c", "start", url).Start()
}
