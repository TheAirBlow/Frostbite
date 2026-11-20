package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"frostbite/internal/agent"
	agentcaddy "frostbite/internal/agent/caddy"
	"frostbite/internal/common"
	_ "frostbite/internal/core/caddy"
)

// main runs the Caddy daemon.
func main() {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		common.Fatal("config", "err", err)
	}
	common.Init(os.Getenv("FROSTBITE_DEBUG") != "", false)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := agent.New(cfg, agentcaddy.New()).Run(ctx); err != nil {
		common.Fatal("agent exited", "err", err)
	}
}
