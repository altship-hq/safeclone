package report

import "testing"

func TestCalculate_safe(t *testing.T) {
	r := &Report{}
	r.Calculate()
	if r.Verdict != "safe" {
		t.Errorf("expected safe, got %s", r.Verdict)
	}
	if r.TotalIssues != 0 {
		t.Errorf("expected 0 issues, got %d", r.TotalIssues)
	}
}

func TestCalculate_warning_vulns(t *testing.T) {
	r := &Report{Vulns: []Vuln{{Package: "lodash", Count: 2, Severity: "medium"}}}
	r.Calculate()
	if r.Verdict != "warning" {
		t.Errorf("expected warning, got %s", r.Verdict)
	}
	if r.TotalIssues != 1 {
		t.Errorf("expected 1 issue, got %d", r.TotalIssues)
	}
}

func TestCalculate_warning_scripts(t *testing.T) {
	r := &Report{Scripts: []Script{{File: "package.json", Reason: "curl", Severity: "high"}}}
	r.Calculate()
	if r.Verdict != "warning" {
		t.Errorf("expected warning, got %s", r.Verdict)
	}
}

func TestCalculate_dangerous(t *testing.T) {
	r := &Report{
		Secrets: []Secret{{File: "main.go", Detector: "AWS", Severity: "high"}},
		Vulns:   []Vuln{{Package: "lodash", Count: 1, Severity: "medium"}},
	}
	r.Calculate()
	if r.Verdict != "dangerous" {
		t.Errorf("expected dangerous, got %s", r.Verdict)
	}
	if r.TotalIssues != 2 {
		t.Errorf("expected 2 issues, got %d", r.TotalIssues)
	}
}
