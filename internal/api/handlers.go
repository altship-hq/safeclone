package api

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/altship-hq/safeclone/internal/worker"
)

// getLatestCommitHash runs `git ls-remote` to fetch the HEAD commit hash for a
// GitHub repo without cloning it. This lets us key the cache on exact repo state
// so any push immediately busts old cached results.
func getLatestCommitHash(repoURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "--quiet", repoURL, "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git ls-remote: %w", err)
	}
	// output format: "<hash>\tHEAD\n"
	parts := strings.Fields(string(out))
	if len(parts) == 0 {
		return "", fmt.Errorf("empty output from git ls-remote")
	}
	return parts[0], nil
}

type scanRequest struct {
	URL string `json:"url" binding:"required"`
}

func (s *Server) handleScan(c *gin.Context) {
	var req scanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !strings.Contains(req.URL, "github.com") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL must be a GitHub repository"})
		return
	}

	// Resolve the current HEAD commit hash so the cache is keyed on exact repo
	// state. Any push to the repo produces a new hash → instant cache bust.
	commitHash, _ := getLatestCommitHash(req.URL)

	// Only serve from cache when we have a valid hash — avoids matching stale
	// results when the hash lookup fails.
	if commitHash != "" {
		if cached, _ := s.db.GetCachedScan(req.URL, commitHash); cached != nil {
			c.JSON(http.StatusOK, gin.H{"job_id": cached.ID, "cached": true})
			return
		}
	}

	jobID := uuid.New().String()
	if err := s.db.CreateScan(jobID, req.URL, commitHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan"})
		return
	}

	task, err := worker.NewScanTask(jobID, req.URL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create task"})
		return
	}
	if _, err := s.client.Enqueue(task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"job_id": jobID, "cached": false})
}

func (s *Server) handleReport(c *gin.Context) {
	jobID := c.Param("jobID")
	scan, err := s.db.GetScan(jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if scan == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": scan.Status, "report": scan.Report, "logs": scan.Logs})
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
