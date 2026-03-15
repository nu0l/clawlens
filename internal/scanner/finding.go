package scanner

import (
	"cmp"
	"slices"
	"time"
)

// Severity represents the risk level of a finding.
type Severity int

const (
	Clean    Severity = 0
	Info     Severity = 1
	Warning  Severity = 2
	Critical Severity = 3
)

func (s Severity) String() string {
	switch s {
	case Clean:
		return "CLEAN"
	case Info:
		return "INFO"
	case Warning:
		return "WARNING"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Category represents the type of detection check.
type Category string

const (
	CatInstallation Category = "installation"
	CatProcess      Category = "process"
	CatService      Category = "service"
	CatConfig       Category = "config"
	CatCredentials  Category = "credentials"
)

func (c Category) Label() string {
	switch c {
	case CatInstallation:
		return "Installation"
	case CatProcess:
		return "Processes"
	case CatService:
		return "Services"
	case CatConfig:
		return "Configuration"
	case CatCredentials:
		return "Credentials"
	default:
		return string(c)
	}
}

// Finding represents a single detection result.
type Finding struct {
	Category    Category          `json:"category"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Details     map[string]string `json:"details,omitempty"`
}

// ScanIssue records a non-fatal check failure. The scan still completes, but
// the result may have limited visibility for the affected area.
type ScanIssue struct {
	Check string `json:"check"`
	Error string `json:"error"`
}

// ScanResult holds all findings from a scan.
type ScanResult struct {
	Hostname    string      `json:"hostname"`
	OS          string      `json:"os"`
	Arch        string      `json:"arch"`
	ScanTime    time.Time   `json:"scan_time"`
	Findings    []Finding   `json:"findings"`
	Issues      []ScanIssue `json:"issues,omitempty"`
	MaxSeverity Severity    `json:"max_severity"`
}

// AddFinding appends a finding and updates MaxSeverity.
func (r *ScanResult) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	if f.Severity > r.MaxSeverity {
		r.MaxSeverity = f.Severity
	}
}

// AddFindings appends findings in order and keeps the highest severity.
func (r *ScanResult) AddFindings(findings []Finding) {
	for _, finding := range findings {
		r.AddFinding(finding)
	}
}

// AddIssue records a non-fatal scan issue.
func (r *ScanResult) AddIssue(check string, err error) {
	if err == nil {
		return
	}
	r.Issues = append(r.Issues, ScanIssue{
		Check: check,
		Error: err.Error(),
	})
}

// CountBySeverity returns the number of findings at each severity level.
func (r *ScanResult) CountBySeverity() map[Severity]int {
	counts := map[Severity]int{
		Clean:    0,
		Info:     0,
		Warning:  0,
		Critical: 0,
	}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// Finalize normalizes result ordering for stable console, JSON, and HTML
// output.
func (r *ScanResult) Finalize() {
	slices.SortStableFunc(r.Findings, compareFinding)
	slices.SortStableFunc(r.Issues, func(a, b ScanIssue) int {
		if diff := cmp.Compare(a.Check, b.Check); diff != 0 {
			return diff
		}
		return cmp.Compare(a.Error, b.Error)
	})
}

func compareFinding(a, b Finding) int {
	if diff := cmp.Compare(int(b.Severity), int(a.Severity)); diff != 0 {
		return diff
	}
	if diff := cmp.Compare(categoryRank(a.Category), categoryRank(b.Category)); diff != 0 {
		return diff
	}
	return cmp.Compare(a.Title, b.Title)
}

func categoryRank(category Category) int {
	switch category {
	case CatInstallation:
		return 0
	case CatProcess:
		return 1
	case CatService:
		return 2
	case CatConfig:
		return 3
	case CatCredentials:
		return 4
	default:
		return 99
	}
}
