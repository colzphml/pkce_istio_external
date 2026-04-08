package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/colzphml/pkce_istio_external/internal/app"
	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/logging"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	logger := logging.New(cfg.Log.Level)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, logger); err != nil {
		logger.Error("application exited with error", "error", err)
		log.Fatalf("run app: %v", err)
	}
}
