package platform

import (
	"path/filepath"
	"strings"
)

func parseUnixPSOutput(output []byte) []ProcessInfo {
	var processes []ProcessInfo

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		command := fields[10]
		if !isOpenClawCommand(command) {
			continue
		}

		processes = append(processes, ProcessInfo{
			PID:  fields[1],
			Name: filepath.Base(command),
			Cmd:  strings.Join(fields[10:], " "),
		})
	}

	return processes
}

func isOpenClawCommand(command string) bool {
	command = strings.ToLower(filepath.Base(command))
	return command == "openclaw" ||
		command == "openclaw-gateway" ||
		strings.HasPrefix(command, "openclaw-")
}
