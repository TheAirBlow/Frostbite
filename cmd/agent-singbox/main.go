package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"frostbite/internal/agent"
	agentsingbox "frostbite/internal/agent/singbox"
	"frostbite/internal/common"
	_ "frostbite/internal/core/singbox"
)

// main runs the sing-box daemon.
func main() {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		common.Fatal("config", "err", err)
	}
	common.Init(os.Getenv("FROSTBITE_DEBUG") != "", false)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := agent.New(cfg, agentsingbox.New(cfg.DataDir)).Run(ctx); err != nil {
		common.Fatal("agent exited", "err", err)
	}
}
