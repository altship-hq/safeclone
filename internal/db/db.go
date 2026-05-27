package db

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/altship-hq/safeclone/internal/report"
	_ "modernc.org/sqlite"
)

// Scan represents a stored scan job.
type Scan struct {
	ID        string
	URL       string
	Status    string
	Report    *report.Report
	Logs      []string
	CreatedAt time.Time
}

// DB wraps the SQLite connection.
type DB struct {
	conn *sql.DB
}

// New opens (or creates) a SQLite file and runs migrations.
func New(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	_, err := d.conn.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id          TEXT PRIMARY KEY,
			url         TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'pending',
			report      TEXT,
			error       TEXT,
			logs        TEXT,
			commit_hash TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);
	`)
	if err != nil {
		return err
	}
	// Add columns to existing databases that predate these migrations.
	_, _ = d.conn.Exec(`ALTER TABLE scans ADD COLUMN logs TEXT`)
	_, _ = d.conn.Exec(`ALTER TABLE scans ADD COLUMN commit_hash TEXT NOT NULL DEFAULT ''`)
	return nil
}

// CreateScan inserts a new scan row with pending status.
func (d *DB) CreateScan(id, url, commitHash string) error {
	_, err := d.conn.Exec(`INSERT INTO scans (id, url, commit_hash) VALUES (?, ?, ?)`, id, url, commitHash)
	return err
}

// UpdateStatus changes the status of a scan.
func (d *DB) UpdateStatus(id, status string) error {
	_, err := d.conn.Exec(`UPDATE scans SET status=? WHERE id=?`, status, id)
	return err
}

// SaveReport marshals the report to JSON and persists it, marking the scan as done.
func (d *DB) SaveReport(id string, rep *report.Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = d.conn.Exec(`UPDATE scans SET status='done', report=? WHERE id=?`, string(data), id)
	return err
}

// AppendLog appends a single log line to the scan's log buffer.
func (d *DB) AppendLog(id, line string) error {
	_, err := d.conn.Exec(`
		UPDATE scans SET logs = CASE WHEN logs IS NULL OR logs = ''
			THEN ? ELSE logs || char(10) || ? END
		WHERE id=?`, line, line, id)
	return err
}

// GetScan fetches a scan by ID. Returns nil, nil if not found.
func (d *DB) GetScan(id string) (*Scan, error) {
	row := d.conn.QueryRow(`SELECT id, url, status, report, logs, created_at FROM scans WHERE id=?`, id)
	return scanRow(row)
}

// GetCachedScan returns a completed scan for the given URL + commit hash done within the last 6 hours.
// Pass a non-empty commitHash to get an exact cache hit keyed to that repo state.
func (d *DB) GetCachedScan(url, commitHash string) (*Scan, error) {
	row := d.conn.QueryRow(`
		SELECT id, url, status, report, logs, created_at FROM scans
		WHERE url=? AND commit_hash=? AND status='done' AND created_at >= datetime('now', '-6 hours')
		ORDER BY created_at DESC LIMIT 1
	`, url, commitHash)
	return scanRow(row)
}

func scanRow(row *sql.Row) (*Scan, error) {
	var s Scan
	var reportJSON sql.NullString
	var logsRaw sql.NullString
	var createdAt string

	err := row.Scan(&s.ID, &s.URL, &s.Status, &reportJSON, &logsRaw, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)

	if reportJSON.Valid && reportJSON.String != "" {
		var rep report.Report
		if err := json.Unmarshal([]byte(reportJSON.String), &rep); err != nil {
			return nil, err
		}
		s.Report = &rep
	}

	if logsRaw.Valid && logsRaw.String != "" {
		s.Logs = strings.Split(logsRaw.String, "\n")
	}

	return &s, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}
