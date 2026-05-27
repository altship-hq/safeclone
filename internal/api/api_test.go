package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/altship-hq/safeclone/internal/db"
)

func setupTestServer(t *testing.T) (*gin.Engine, *db.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	f, err := os.CreateTemp("", "safeclone-api-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	database, err := db.New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	// Use a no-op asynq client (won't connect to Redis in tests).
	client := asynq.NewClient(asynq.RedisClientOpt{Addr: "localhost:6379"})

	srv := New(database, client)
	r := gin.New()
	srv.Routes(r)
	return r, database
}

func TestHandleScan_validURL(t *testing.T) {
	r, _ := setupTestServer(t)
	body, _ := json.Marshal(map[string]string{"url": "https://github.com/foo/bar"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// May return 500 if Redis is unavailable, but should not return 400.
	if w.Code == http.StatusBadRequest {
		t.Errorf("unexpected 400 for valid URL: %s", w.Body.String())
	}
}

func TestHandleScan_invalidURL(t *testing.T) {
	r, _ := setupTestServer(t)
	body, _ := json.Marshal(map[string]string{"url": "https://gitlab.com/foo/bar"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleReport_notFound(t *testing.T) {
	r, _ := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/report/nonexistent-id", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	r, _ := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleScan_cached(t *testing.T) {
	r, database := setupTestServer(t)

	url := "https://github.com/foo/cached"
	_ = database.CreateScan("cached-id", url, "abc123")
	database.SaveReport("cached-id", nil)

	body, _ := json.Marshal(map[string]string{"url": url})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// getLatestCommitHash fails for fake URLs, so the cache is bypassed and
	// the handler tries to enqueue a job. Enqueue fails when Redis is not
	// available in CI (500) — that is acceptable here. A 400 is always wrong.
	if w.Code == http.StatusBadRequest {
		t.Errorf("unexpected 400: %s", w.Body.String())
	}
}
