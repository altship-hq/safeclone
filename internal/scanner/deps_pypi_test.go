package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDependencies_pypi(t *testing.T) {
	if !hasInternet() {
		t.Skip("no internet access")
	}

	dir := t.TempDir()
	// requests 2.6.0 has known CVEs
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.6.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	vulns, err := ScanDependencies(dir)
	if err != nil {
		t.Fatalf("ScanDependencies error: %v", err)
	}
	if len(vulns) == 0 {
		t.Error("expected at least one vuln for requests 2.6.0")
	}
}

func TestScanDependencies_requirementsComments(t *testing.T) {
	if !hasInternet() {
		t.Skip("no internet access")
	}

	dir := t.TempDir()
	content := "# this is a comment\n\nnon-existent-package-xyz==1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// should not error — just returns empty if no vulns
	_, err := ScanDependencies(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
