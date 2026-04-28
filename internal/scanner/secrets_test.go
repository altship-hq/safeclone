package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// makeFakeTrufflehog writes a shell script that emits output to a temp dir,
// then prepends that dir to PATH so exec.Command picks it up.
func makeFakeTrufflehog(t *testing.T, output string) {
	t.Helper()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "output.json")
	if err := os.WriteFile(outFile, []byte(output), 0644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat " + outFile + "\n"
	bin := filepath.Join(dir, "trufflehog")
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

const sampleFinding = `{"DetectorName":"AWS","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"/repo/config.txt"}}}}`

func TestScanSecrets_parsesVerifiedFinding(t *testing.T) {
	makeFakeTrufflehog(t, sampleFinding+"\n")
	secrets, err := ScanSecrets(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("want 1 secret, got %d", len(secrets))
	}
	s := secrets[0]
	if s.Detector != "AWS" {
		t.Errorf("want Detector=AWS, got %q", s.Detector)
	}
	if s.File != "/repo/config.txt" {
		t.Errorf("want File=/repo/config.txt, got %q", s.File)
	}
	if !s.Verified {
		t.Error("want Verified=true")
	}
	if s.Severity != "high" {
		t.Errorf("want Severity=high, got %q", s.Severity)
	}
}

func TestScanSecrets_emptyOutput(t *testing.T) {
	makeFakeTrufflehog(t, "")
	secrets, err := ScanSecrets(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("want 0 secrets, got %d", len(secrets))
	}
}

func TestScanSecrets_skipsInvalidJSON(t *testing.T) {
	makeFakeTrufflehog(t, "not-json\n"+sampleFinding+"\n")
	secrets, err := ScanSecrets(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("want 1 secret (invalid line skipped), got %d", len(secrets))
	}
}

func TestScanSecrets_skipsRowWithoutDetector(t *testing.T) {
	noDetector := `{"DetectorName":"","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"/repo/x.txt"}}}}`
	makeFakeTrufflehog(t, noDetector+"\n")
	secrets, err := ScanSecrets(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("want 0 secrets for missing DetectorName, got %d", len(secrets))
	}
}
