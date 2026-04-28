package worker

import (
	"encoding/json"
	"testing"
)

func TestNewScanTask(t *testing.T) {
	task, err := NewScanTask("job-123", "https://github.com/foo/bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Type() != TaskScan {
		t.Errorf("expected task type %s, got %s", TaskScan, task.Type())
	}
	var payload ScanPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.JobID != "job-123" {
		t.Errorf("expected job-123, got %s", payload.JobID)
	}
	if payload.URL != "https://github.com/foo/bar" {
		t.Errorf("expected URL mismatch: %s", payload.URL)
	}
}

func TestNewScanHandler_notNil(t *testing.T) {
	h := NewScanHandler(nil, nil)
	if h == nil {
		t.Error("expected non-nil handler")
	}
}
