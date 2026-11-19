package agent_test

import (
	"frostbite/internal/agent"
	"frostbite/internal/agent/mtproto"
	"frostbite/internal/agent/singbox"
	"frostbite/internal/agent/xray"
)

// Every core that can sit in front of a real site must be stoppable by the guard.
var (
	_ agent.Supervised = (*xray.Runtime)(nil)
	_ agent.Supervised = (*singbox.Runtime)(nil)
	_ agent.Supervised = (*mtproto.Runtime)(nil)
)
