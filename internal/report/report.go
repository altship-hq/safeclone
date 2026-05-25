package report

// Secret represents a detected hardcoded credential or token.
type Secret struct {
	File     string `json:"file"`
	Detector string `json:"detector"`
	Severity string `json:"severity"`
	Verified bool   `json:"verified"`
}

// Vuln represents a vulnerable dependency.
type Vuln struct {
	Package  string `json:"package"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

// Script represents a dangerous pattern found in an install hook.
type Script struct {
	File     string `json:"file"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
}

// MarkdownIssue represents a suspicious finding inside a markdown file.
type MarkdownIssue struct {
	File     string `json:"file"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
	Category string `json:"category"` // "prompt_injection" | "malicious_code"
}

// Report aggregates all scanner results.
type Report struct {
	Secrets        []Secret        `json:"secrets"`
	Vulns          []Vuln          `json:"vulns"`
	Scripts        []Script        `json:"scripts"`
	MarkdownIssues []MarkdownIssue `json:"markdown_issues,omitempty"`
	Verdict        string          `json:"verdict"`
	TotalIssues    int             `json:"total_issues"`
}

// Calculate sets TotalIssues and Verdict based on current findings.
func (r *Report) Calculate() {
	r.TotalIssues = len(r.Secrets) + len(r.Vulns) + len(r.Scripts) + len(r.MarkdownIssues)

	switch {
	case len(r.Secrets) > 0:
		r.Verdict = "dangerous"
	case len(r.Vulns) > 0 || len(r.Scripts) > 0 || len(r.MarkdownIssues) > 0:
		r.Verdict = "warning"
	default:
		r.Verdict = "safe"
	}
}
