package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/altship-hq/safeclone/internal/report"
)

var (
	flagDir   string
	flagForce bool
)

func apiBase() string {
	if v := os.Getenv("SAFECLONE_API"); v != "" {
		return v
	}
	return "https://api.safeclone.dev"
}

var root = &cobra.Command{
	Use:   "safeclone <url>",
	Short: "Scan a GitHub repo for threats before cloning",
	Args:  cobra.ExactArgs(1),
	RunE:  run,
}

func main() {
	root.Flags().StringVarP(&flagDir, "dir", "d", "", "destination folder name")
	root.Flags().BoolVar(&flagForce, "force", false, "clone without prompting even if issues found")
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	url := args[0]
	dest := flagDir
	if dest == "" {
		parts := strings.Split(strings.TrimSuffix(url, ".git"), "/")
		dest = parts[len(parts)-1]
	}

	bold := color.New(color.Bold)
	bold.Println("🛡️  SafeClone")

	jobID, cached, err := postScan(url)
	if err != nil {
		return fmt.Errorf("scan request failed: %w", err)
	}
	if cached {
		color.New(color.Faint).Println("using cached result")
	} else {
		fmt.Println("scanning in sandbox (~30-60s)")
	}

	rep, err := pollReport(jobID)
	if err != nil {
		return fmt.Errorf("polling failed: %w", err)
	}

	printReport(rep)

	if !flagForce {
		if !confirmClone(rep.Verdict) {
			fmt.Println("aborted.")
			return nil
		}
	}

	fmt.Printf("cloning into %s ...\n", dest)
	out, err := exec.Command("git", "clone", url, dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s", string(out))
	}
	color.Green("done.")
	return nil
}

func postScan(url string) (string, bool, error) {
	body, _ := json.Marshal(map[string]string{"url": url})
	resp, err := http.Post(apiBase()+"/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	var result struct {
		JobID  string `json:"job_id"`
		Cached bool   `json:"cached"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", false, err
	}
	return result.JobID, result.Cached, nil
}

func pollReport(jobID string) (*report.Report, error) {
	for {
		time.Sleep(2 * time.Second)
		resp, err := http.Get(apiBase() + "/report/" + jobID)
		if err != nil {
			return nil, err
		}
		var result struct {
			Status string         `json:"status"`
			Report *report.Report `json:"report"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch result.Status {
		case "done":
			return result.Report, nil
		case "failed":
			return nil, fmt.Errorf("scan failed on server")
		}
	}
}

func printReport(rep *report.Report) {
	fmt.Println()
	if len(rep.Secrets) > 0 {
		color.Red("Secrets found:")
		for _, s := range rep.Secrets {
			color.Red("  [%s] %s — %s", s.Severity, s.Detector, s.File)
		}
	} else {
		color.Green("  ✓ No secrets")
	}

	if len(rep.Vulns) > 0 {
		color.Yellow("Vulnerable dependencies:")
		for _, v := range rep.Vulns {
			color.Yellow("  [%s] %s (%d CVEs)", v.Severity, v.Package, v.Count)
		}
	} else {
		color.Green("  ✓ No vulnerable dependencies")
	}

	if len(rep.Scripts) > 0 {
		color.Yellow("Dangerous install scripts:")
		for _, sc := range rep.Scripts {
			color.Yellow("  [%s] %s — %s", sc.Severity, sc.Reason, sc.File)
		}
	} else {
		color.Green("  ✓ No dangerous scripts")
	}

	fmt.Println()
	switch rep.Verdict {
	case "safe":
		color.Green("Verdict: SAFE")
	case "warning":
		color.Yellow("Verdict: WARNING")
	case "dangerous":
		color.Red("Verdict: DANGEROUS")
	}
	fmt.Println()
}

func confirmClone(verdict string) bool {
	switch verdict {
	case "safe":
		return true
	case "warning":
		fmt.Print("Issues found. Clone anyway? [y/N] ")
	case "dangerous":
		color.Red("WARNING: dangerous content detected.")
		fmt.Print("Clone anyway? [y/N] ")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}
