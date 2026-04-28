package db

import (
	"os"
	"testing"
	"time"

	"github.com/altship-hq/safeclone/internal/report"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	f, err := os.CreateTemp("", "safeclone-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	d, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestCreateScan(t *testing.T) {
	d := newTestDB(t)
	if err := d.CreateScan("id1", "https://github.com/foo/bar"); err != nil {
		t.Fatal(err)
	}
	s, err := d.GetScan("id1")
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("expected scan, got nil")
	}
	if s.Status != "pending" {
		t.Errorf("expected pending, got %s", s.Status)
	}
}

func TestUpdateStatus(t *testing.T) {
	d := newTestDB(t)
	d.CreateScan("id2", "https://github.com/foo/bar")
	if err := d.UpdateStatus("id2", "scanning"); err != nil {
		t.Fatal(err)
	}
	s, _ := d.GetScan("id2")
	if s.Status != "scanning" {
		t.Errorf("expected scanning, got %s", s.Status)
	}
}

func TestSaveAndGetReport(t *testing.T) {
	d := newTestDB(t)
	d.CreateScan("id3", "https://github.com/foo/bar")

	rep := &report.Report{
		Secrets: []report.Secret{{File: "config.go", Detector: "AWS", Severity: "high"}},
		Verdict: "dangerous",
	}
	rep.Calculate()

	if err := d.SaveReport("id3", rep); err != nil {
		t.Fatal(err)
	}

	s, err := d.GetScan("id3")
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != "done" {
		t.Errorf("expected done, got %s", s.Status)
	}
	if s.Report == nil {
		t.Fatal("expected report, got nil")
	}
	if s.Report.Verdict != "dangerous" {
		t.Errorf("expected dangerous, got %s", s.Report.Verdict)
	}
}

func TestGetScan_notFound(t *testing.T) {
	d := newTestDB(t)
	s, err := d.GetScan("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Error("expected nil for unknown id")
	}
}

func TestGetCachedScan(t *testing.T) {
	d := newTestDB(t)
	url := "https://github.com/foo/bar"
	d.CreateScan("old1", url)
	// manually set old created_at
	d.conn.Exec(`UPDATE scans SET created_at=?, status='done', report='{"verdict":"safe"}' WHERE id='old1'`,
		time.Now().UTC().Add(-8*time.Hour).Format("2006-01-02 15:04:05"))

	s, err := d.GetCachedScan(url)
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Error("expected nil for scan older than 6 hours")
	}

	// recent scan
	d.CreateScan("new1", url)
	rep := &report.Report{Verdict: "safe"}
	d.SaveReport("new1", rep)

	s, err = d.GetCachedScan(url)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Error("expected cached scan for recent entry")
	}
}
