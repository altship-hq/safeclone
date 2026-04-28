package api

import (
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/altship-hq/safeclone/internal/db"
)

// Server holds dependencies for the HTTP API.
type Server struct {
	db     *db.DB
	client *asynq.Client
}

// New creates a new Server.
func New(database *db.DB, client *asynq.Client) *Server {
	return &Server{db: database, client: client}
}

// Routes registers all HTTP routes on the given Gin engine.
func (s *Server) Routes(r *gin.Engine) {
	r.POST("/scan", s.handleScan)
	r.GET("/report/:jobID", s.handleReport)
	r.GET("/health", s.handleHealth)
}
