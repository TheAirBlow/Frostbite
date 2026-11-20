#!/bin/sh
# Tests the gate and the agent against the patched Caddy that build.sh prepares.
set -eu
cd "$(dirname "$0")"
bin="$(mktemp -d)/naive-caddy"
./build.sh "$bin" >/dev/null
go test -modfile=.build/go.mod -count=1 "$@" ./...
cd ..
FROSTBITE_NAIVE_BIN="$bin" go test -count=1 "$@" ./internal/agent/naive/ ./internal/core/naive/
