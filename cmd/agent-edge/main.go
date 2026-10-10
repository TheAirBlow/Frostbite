package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"frostbite/internal/agent"
	agentedge "frostbite/internal/agent/edge"
	"frostbite/internal/common"
	_ "frostbite/internal/core/edge"
)

// main runs the edge daemon.
func main() {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		common.Fatal("config", "err", err)
	}
	common.Init(os.Getenv("FROSTBITE_DEBUG") != "", false)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := agent.New(cfg, agentedge.New()).Run(ctx); err != nil {
		common.Fatal("agent exited", "err", err)
	}
}
