package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// ScanCredentials checks for credential files and their permissions.
func ScanCredentials(homeDir string) ([]Finding, error) {
	var findings []Finding

	credsDir := filepath.Join(homeDir, "credentials")
	info, err := os.Stat(credsDir)
	if err != nil || !info.IsDir() {
		if errors.Is(err, fs.ErrNotExist) || err == nil {
			return findings, nil
		}
		return findings, err
	}

	files, err := credentialFiles(credsDir)
	if err != nil {
		return findings, err
	}
	if len(files) == 0 {
		return findings, nil
	}

	findings = append(findings, Finding{
		Category:    CatCredentials,
		Title:       "Credentials directory exists",
		Description: "The credentials directory contains files that may include API keys or tokens.",
		Severity:    Warning,
		Details:     map[string]string{"path": credsDir, "file_count": strconv.Itoa(len(files))},
	})

	// Check permissions (Unix only)
	if runtime.GOOS == "windows" {
		return findings, nil
	}

	for _, path := range files {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := fi.Mode().Perm()
		// Check if world-readable (others have read permission)
		if mode&fs.FileMode(0o004) != 0 {
			findings = append(findings, Finding{
				Category:    CatCredentials,
				Title:       "Credential file has world-readable permissions",
				Description: "A credential file can be read by any user on the system.",
				Severity:    Critical,
				Details: map[string]string{
					"path":        path,
					"permissions": mode.String(),
				},
			})
		}
	}

	return findings, nil
}

func credentialFiles(root string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
