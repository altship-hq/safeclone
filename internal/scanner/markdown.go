package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/altship-hq/safeclone/internal/report"
)

// aiConfigFiles are files that AI coding assistants auto-read — highest priority targets.
var aiConfigFiles = map[string]bool{
	"CLAUDE.md":                       true,
	"AGENTS.md":                       true,
	".cursorrules":                    true,
	"copilot-instructions.md":         true,
	".github/copilot-instructions.md": true,
}

type mdPattern struct {
	re     *regexp.Regexp
	reason string
}

var promptInjectionPatterns = []mdPattern{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions?`), "prompt injection: ignore previous instructions"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|your|prior)`), "prompt injection: disregard directive"},
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+(a\s+)?(different|new|unrestricted)`), "prompt injection: role override"},
	{regexp.MustCompile(`(?i)forget\s+(everything|all\s+previous|your\s+previous)`), "prompt injection: memory wipe directive"},
	{regexp.MustCompile(`(?i)<\s*system\s*>|<\|im_start\|>\s*system`), "prompt injection: system prompt tag"},
	{regexp.MustCompile(`(?i)new\s+(primary\s+)?instructions?\s*:`), "prompt injection: instruction override"},
	{regexp.MustCompile(`(?i)your\s+(new\s+)?(primary\s+)?instructions?\s+are\s*:`), "prompt injection: instruction override"},
	{regexp.MustCompile(`(?i)<!--\s*[Ll][Ll][Mm][\s\S]{0,30}:`), "hidden LLM instruction in HTML comment"},
	{regexp.MustCompile(`(?i)do\s+not\s+(follow|adhere\s+to|comply\s+with)\s+.{0,40}(previous|prior|original)`), "prompt injection: compliance override"},
}

var maliciousCodeInMDPatterns = []mdPattern{
	{regexp.MustCompile(`curl\s+.+\|\s*(ba)?sh`), "remote code execution via curl | sh"},
	{regexp.MustCompile(`wget\s+.+\|\s*(ba)?sh`), "remote code execution via wget | sh"},
	{regexp.MustCompile(`eval\s*\(`), "dynamic code execution (eval)"},
	{regexp.MustCompile(`(?i)base64\s*(-d|--decode)`), "base64 decoding (potential obfuscation)"},
	{regexp.MustCompile(`rm\s+-rf\s+[/~$\\*]`), "destructive filesystem operation (rm -rf)"},
}

var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
}

// ScanMarkdown scans .md files and AI config files for prompt injection and malicious code blocks.
func ScanMarkdown(dir string) []report.MarkdownIssue {
	var issues []report.MarkdownIssue

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(dir, path)
		base := filepath.Base(path)
		ext := strings.ToLower(filepath.Ext(path))

		isMD := ext == ".md"
		isAIConfig := aiConfigFiles[base] || aiConfigFiles[filepath.ToSlash(rel)]

		if !isMD && !isAIConfig {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(content)

		// Scan full text for prompt injection patterns.
		for _, p := range promptInjectionPatterns {
			if p.re.MatchString(text) {
				sev := "medium"
				if isAIConfig {
					sev = "high"
				}
				issues = append(issues, report.MarkdownIssue{
					File:     rel,
					Reason:   p.reason,
					Severity: sev,
					Category: "prompt_injection",
				})
				break // one prompt injection issue per file
			}
		}

		// Scan fenced code blocks for malicious shell patterns.
		for _, block := range extractCodeBlocks(text) {
			for _, p := range maliciousCodeInMDPatterns {
				if p.re.MatchString(block) {
					issues = append(issues, report.MarkdownIssue{
						File:     rel,
						Reason:   p.reason,
						Severity: "medium",
						Category: "malicious_code",
					})
					break // one malicious code issue per block
				}
			}
		}

		return nil
	})

	return issues
}

// extractCodeBlocks returns the contents of all fenced code blocks in markdown text.
func extractCodeBlocks(text string) []string {
	var blocks []string
	lines := strings.Split(text, "\n")
	inBlock := false
	var cur strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if inBlock {
				blocks = append(blocks, cur.String())
				cur.Reset()
				inBlock = false
			} else {
				inBlock = true
			}
			continue
		}
		if inBlock {
			cur.WriteString(line + "\n")
		}
	}

	return blocks
}
