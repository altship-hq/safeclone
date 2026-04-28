package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/altship-hq/safeclone/internal/report"
)

type truffleHogLine struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

var excludedPaths = []string{
	"testdata",
	"fixtures",
	"test",
	"mocks",
	"examples",
}

// ScanSecrets runs TruffleHog against the given directory and returns verified secrets.
func ScanSecrets(ctx context.Context, dir string) ([]report.Secret, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	excFile, err := os.CreateTemp("", "trufflehog-exclude-*")
	if err != nil {
		return nil, err
	}
	excPath := excFile.Name()
	defer os.Remove(excPath)
	if err := os.WriteFile(excPath, []byte(strings.Join(excludedPaths, "\n")+"\n"), 0600); err != nil {
		excFile.Close()
		return nil, err
	}
	excFile.Close()

	cmd := exec.CommandContext(ctx, "trufflehog", "filesystem", dir,
		"--json", "--no-update", "--only-verified",
		"--exclude-paths="+excPath,
	)
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, err
		}
	}

	var secrets []report.Secret
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		var row truffleHogLine
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if row.DetectorName == "" {
			continue
		}
		secrets = append(secrets, report.Secret{
			File:     row.SourceMetadata.Data.Filesystem.File,
			Detector: row.DetectorName,
			Severity: "high",
			Verified: row.Verified,
		})
	}
	return secrets, sc.Err()
}
