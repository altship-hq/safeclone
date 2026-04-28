package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/altship-hq/safeclone/internal/api"
	"github.com/altship-hq/safeclone/internal/db"
	"github.com/altship-hq/safeclone/internal/worker"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	dbPath := getenv("DATABASE_PATH", "./safeclone.db")
	port := getenv("PORT", "3001")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")

	database, err := db.New(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	redisOpt := asynq.RedisClientOpt{Addr: redisAddr}
	client := asynq.NewClient(redisOpt)
	defer client.Close()

	runner, err := worker.NewRunner()
	if err != nil {
		log.Fatalf("init runner: %v", err)
	}

	// Start the Asynq worker in a goroutine.
	go func() {
		srv := asynq.NewServer(redisOpt, asynq.Config{Concurrency: 3})
		mux := asynq.NewServeMux()
		mux.Handle(worker.TaskScan, worker.NewScanHandler(runner, database))
		if err := srv.Run(mux); err != nil {
			log.Printf("asynq worker stopped: %v", err)
		}
	}()

	r := gin.Default()
	apiSrv := api.New(database, client)
	apiSrv.Routes(r)

	httpSrv := &http.Server{Addr: ":" + port, Handler: r}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("SafeClone server running on :%s", port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down...")
	httpSrv.Shutdown(context.Background())
}
