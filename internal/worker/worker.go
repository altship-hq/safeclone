package worker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/altship-hq/safeclone/internal/db"
)

const TaskScan = "scan:repo"

// ScanPayload is the job payload for a scan task.
type ScanPayload struct {
	JobID string `json:"job_id"`
	URL   string `json:"url"`
}

// NewScanTask creates an asynq task for scanning a repo.
func NewScanTask(jobID, url string) (*asynq.Task, error) {
	payload, err := json.Marshal(ScanPayload{JobID: jobID, URL: url})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskScan, payload), nil
}

// ScanHandler processes scan jobs.
type ScanHandler struct {
	runner *Runner
	db     *db.DB
}

// NewScanHandler creates a ScanHandler.
func NewScanHandler(runner *Runner, database *db.DB) *ScanHandler {
	return &ScanHandler{runner: runner, db: database}
}

// ProcessTask implements asynq.Handler.
func (h *ScanHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	var payload ScanPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	if err := h.db.UpdateStatus(payload.JobID, "scanning"); err != nil {
		return err
	}

	rep, err := h.runner.Run(ctx, payload.URL)
	if err != nil {
		_ = h.db.UpdateStatus(payload.JobID, "failed")
		return err
	}

	return h.db.SaveReport(payload.JobID, rep)
}
