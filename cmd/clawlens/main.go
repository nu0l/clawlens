package main

import (
	"os"

	"github.com/clawlens/clawlens/internal/app"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr, app.Config{
		Version: version,
		Commit:  commit,
	}))
}
