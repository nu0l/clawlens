package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"

	"github.com/clawlens/clawlens/internal/scanner"
)

//go:embed template/report.html
var templateFS embed.FS

var funcMap = template.FuncMap{
	"severityClass": func(s scanner.Severity) string {
		switch s {
		case scanner.Critical:
			return "critical"
		case scanner.Warning:
			return "warning"
		case scanner.Info:
			return "info"
		default:
			return "clean"
		}
	},
}

// WriteHTML renders the scan result as an HTML report to the given writer.
func WriteHTML(w io.Writer, result *scanner.ScanResult, version string) error {
	tmplContent, err := templateFS.ReadFile("template/report.html")
	if err != nil {
		return fmt.Errorf("读取内嵌模板失败: %w", err)
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("解析模板失败: %w", err)
	}

	data := NewTemplateData(result, version)
	return tmpl.Execute(w, data)
}
