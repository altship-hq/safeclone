package scanner

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func hasInternet() bool {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.osv.dev/v1/querybatch")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func TestScanDependencies_npm(t *testing.T) {
	if !hasInternet() {
		t.Skip("no internet access")
	}

	dir := t.TempDir()
	pkgJSON := `{"dependencies":{"lodash":"4.17.4"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	vulns, err := ScanDependencies(dir)
	if err != nil {
		t.Fatalf("ScanDependencies error: %v", err)
	}
	if len(vulns) == 0 {
		t.Error("expected at least one vuln for lodash 4.17.4")
	}
}

func TestScanDependencies_empty(t *testing.T) {
	dir := t.TempDir()
	vulns, err := ScanDependencies(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected no vulns for empty dir, got %d", len(vulns))
	}
}

// --- unit tests for version parsers (no network) ---

func TestStripNpmRange(t *testing.T) {
	cases := []struct{ in, want string }{
		{"4.17.4", "4.17.4"},
		{"^4.17.4", "4.17.4"},
		{"~2.0.0", "2.0.0"},
		{">=1.0.0", "1.0.0"},
		{">=1.0.0 <2.0.0", "1.0.0"},
		{"*", ""},
		{"latest", "latest"},
	}
	for _, c := range cases {
		if got := stripNpmRange(c.in); got != c.want {
			t.Errorf("stripNpmRange(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitPyPILine(t *testing.T) {
	cases := []struct{ line, name, ver string }{
		{"requests==2.28.0", "requests", "2.28.0"},
		{"flask>=2.0.0", "flask", "2.0.0"},
		{"django~=3.2.0", "django", "3.2.0"},
		{"numpy", "numpy", ""},
		{"requests[security]==2.28.0", "requests", "2.28.0"},
		{"boto3>=1.0,<2.0", "boto3", "1.0"},
	}
	for _, c := range cases {
		name, ver := splitPyPILine(c.line)
		if name != c.name || ver != c.ver {
			t.Errorf("splitPyPILine(%q) = (%q, %q), want (%q, %q)", c.line, name, ver, c.name, c.ver)
		}
	}
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/app

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.14.0 // indirect
)

require github.com/stretchr/testify v1.8.4
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseGoMod(dir)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["github.com/gin-gonic/gin"]; e.version != "1.9.1" || e.ecosystem != "Go" {
		t.Errorf("unexpected gin entry: %+v", e)
	}
	if e := byName["golang.org/x/crypto"]; e.version != "0.14.0" {
		t.Errorf("unexpected crypto version: %q", e.version)
	}
}

func TestParseCargo(t *testing.T) {
	dir := t.TempDir()
	cargo := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.28.0", features = ["full"] }

[dev-dependencies]
pretty_assertions = "1.4.0"
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargo), 0644); err != nil {
		t.Fatal(err)
	}
	entries := parseCargo(dir)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d: %+v", len(entries), entries)
	}
	byName := map[string]depEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["serde"]; e.version != "1.0" || e.ecosystem != "crates.io" {
		t.Errorf("unexpected serde entry: %+v", e)
	}
	if e := byName["tokio"]; e.version != "1.28.0" {
		t.Errorf("unexpected tokio version: %q", e.version)
	}
	if e := byName["pretty_assertions"]; e.version != "1.4.0" {
		t.Errorf("unexpected pretty_assertions version: %q", e.version)
	}
}
