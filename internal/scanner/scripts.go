package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	"github.com/altship-hq/safeclone/internal/report"
)

type pattern struct {
	re       *regexp.Regexp
	reason   string
	severity string
}

var patterns = []pattern{
	{regexp.MustCompile(`eval\s*\(`), "Dynamic code execution", "critical"},
	{regexp.MustCompile(`exec\s*\(`), "Shell command execution", "critical"},
	{regexp.MustCompile(`base64`), "Obfuscated content", "high"},
	{regexp.MustCompile(`curl\s+http`), "Downloads from internet", "high"},
	{regexp.MustCompile(`wget\s+http`), "Downloads from internet", "high"},
	{regexp.MustCompile(`rm\s+-rf`), "Destructive file deletion", "high"},
	{regexp.MustCompile(`chmod\s+\+x`), "Makes file executable", "medium"},
	{regexp.MustCompile(`process\.env`), "Reads environment variables", "low"},
}

var installHooks = map[string]bool{
	"preinstall":  true,
	"install":     true,
	"postinstall": true,
}

// ScanScripts detects dangerous patterns in install-time scripts.
func ScanScripts(dir string) []report.Script {
	var results []report.Script

	// package.json — only check install hooks
	pkgPath := filepath.Join(dir, "package.json")
	if data, err := os.ReadFile(pkgPath); err == nil {
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			for hook, script := range pkg.Scripts {
				if !installHooks[hook] {
					continue
				}
				for _, p := range patterns {
					if p.re.MatchString(script) {
						results = append(results, report.Script{
							File:     "package.json",
							Reason:   p.reason,
							Severity: p.severity,
						})
					}
				}
			}
		}
	}

	// other files scanned in full
	otherFiles := []string{"setup.py", "setup.cfg", "install.sh", "Makefile"}
	for _, name := range otherFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		content := string(data)
		for _, p := range patterns {
			if p.re.MatchString(content) {
				results = append(results, report.Script{
					File:     name,
					Reason:   p.reason,
					Severity: p.severity,
				})
			}
		}
	}

	return results
}
