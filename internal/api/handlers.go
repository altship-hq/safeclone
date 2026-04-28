package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/altship-hq/safeclone/internal/worker"
)

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

	if cached, _ := s.db.GetCachedScan(req.URL); cached != nil {
		c.JSON(http.StatusOK, gin.H{"job_id": cached.ID, "cached": true})
		return
	}

	jobID := uuid.New().String()
	if err := s.db.CreateScan(jobID, req.URL); err != nil {
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
	c.JSON(http.StatusOK, gin.H{"status": scan.Status, "report": scan.Report})
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
