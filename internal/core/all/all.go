// Package all pulls in every core renderer so they register themselves.
package all

import (
	_ "frostbite/internal/core/edge"
	_ "frostbite/internal/core/mtproto"
	_ "frostbite/internal/core/singbox"
	_ "frostbite/internal/core/turnable"
	_ "frostbite/internal/core/xray"
)
