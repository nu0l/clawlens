package report

import (
	"encoding/json"
	"io"

	"github.com/clawlens/clawlens/internal/scanner"
)

// WriteJSON writes the scan result as JSON to the given writer.
func WriteJSON(w io.Writer, result *scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
