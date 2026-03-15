package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/clawlens/clawlens/internal/scanner"
)

type Format string

const (
	FormatHTML Format = "html"
	FormatJSON Format = "json"
)

func ParseFormat(value string) (Format, error) {
	format := Format(strings.ToLower(value))
	switch format {
	case FormatHTML, FormatJSON:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported format %q (expected html or json)", value)
	}
}

// TemplateData is the data passed to the HTML template.
type TemplateData struct {
	ProductName   string
	Result        *scanner.ScanResult
	Groups        []FindingGroup
	Version       string
	CriticalCount int
	WarningCount  int
	InfoCount     int
	TotalFindings int
}

type FindingGroup struct {
	Key      string
	Label    string
	Findings []scanner.Finding
}

// NewTemplateData creates template data from a scan result.
func NewTemplateData(result *scanner.ScanResult, version string) *TemplateData {
	counts := result.CountBySeverity()
	return &TemplateData{
		ProductName:   "ClawLens",
		Result:        result,
		Groups:        groupFindings(result.Findings),
		Version:       version,
		CriticalCount: counts[scanner.Critical],
		WarningCount:  counts[scanner.Warning],
		InfoCount:     counts[scanner.Info],
		TotalFindings: len(result.Findings),
	}
}

func Write(w io.Writer, format Format, result *scanner.ScanResult, version string) error {
	switch format {
	case FormatJSON:
		return WriteJSON(w, result)
	case FormatHTML:
		return WriteHTML(w, result, version)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func groupFindings(findings []scanner.Finding) []FindingGroup {
	order := []scanner.Category{
		scanner.CatInstallation,
		scanner.CatProcess,
		scanner.CatService,
		scanner.CatConfig,
		scanner.CatCredentials,
	}

	grouped := make(map[scanner.Category][]scanner.Finding)
	for _, finding := range findings {
		grouped[finding.Category] = append(grouped[finding.Category], finding)
	}

	var groups []FindingGroup
	for _, category := range order {
		items := grouped[category]
		if len(items) == 0 {
			continue
		}
		groups = append(groups, FindingGroup{
			Key:      string(category),
			Label:    category.Label(),
			Findings: items,
		})
	}

	for category, items := range grouped {
		if len(items) == 0 || containsCategory(order, category) {
			continue
		}
		groups = append(groups, FindingGroup{
			Key:      string(category),
			Label:    category.Label(),
			Findings: items,
		})
	}

	return groups
}

func containsCategory(categories []scanner.Category, target scanner.Category) bool {
	for _, category := range categories {
		if category == target {
			return true
		}
	}
	return false
}
