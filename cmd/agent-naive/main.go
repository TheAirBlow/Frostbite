package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"frostbite/internal/agent"
	agentnaive "frostbite/internal/agent/naive"
	"frostbite/internal/common"
	_ "frostbite/internal/core/naive"
)

// main runs the naive daemon.
func main() {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		common.Fatal("config", "err", err)
	}
	common.Init(os.Getenv("FROSTBITE_DEBUG") != "", false)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bin := os.Getenv("FROSTBITE_CADDY_BIN")
	if bin == "" {
		bin = "naive-caddy"
	}
	if err := agent.New(cfg, agentnaive.New(bin, cfg.DataDir)).Run(ctx); err != nil {
		common.Fatal("agent exited", "err", err)
	}
}
