package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"frostbite/internal/agent"
	agentxray "frostbite/internal/agent/xray"
	"frostbite/internal/common"
	_ "frostbite/internal/core/xray"
)

// main runs the xray daemon.
func main() {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		common.Fatal("config", "err", err)
	}
	common.Init(os.Getenv("FROSTBITE_DEBUG") != "", false)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bin := os.Getenv("FROSTBITE_XRAY_BIN")
	if bin == "" {
		bin = "xray"
	}
	if err := agent.New(cfg, agentxray.New(bin, cfg.DataDir)).Run(ctx); err != nil {
		common.Fatal("agent exited", "err", err)
	}
}
