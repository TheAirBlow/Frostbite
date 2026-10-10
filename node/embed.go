// Package node ships the files a fresh node needs.
package node

import _ "embed"

// Compose is the docker-compose.yml served to new nodes.
//
//go:embed docker-compose.yml
var Compose []byte
