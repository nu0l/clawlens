//go:build linux || darwin

package platform

import (
	"bufio"
	"os"
	"strings"
)

// findAllUserHomeDirs reads /etc/passwd and returns all user home directories.
func findAllUserHomeDirs() []string {
	var homes []string
	seen := make(map[string]bool)

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return homes
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: username:x:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		home := fields[5]
		if home == "" || seen[home] {
			continue
		}
		seen[home] = true
		homes = append(homes, home)
	}

	return homes
}
