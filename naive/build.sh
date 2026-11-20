#!/bin/sh
# Builds naive-caddy. The NaiveProxy fork of forwardproxy needs a Caddy with the idle timeout override its tunnels use,
# which the fork ships as a patch against the Caddy version named in CADDY_VERSION.
set -eu

cd "$(dirname "$0")"
out="${1:-naive-caddy}"
work="$(pwd)/.build"
fp="$(go list -m -f '{{.Dir}}' github.com/caddyserver/forwardproxy)"
version="$(cat "$fp/CADDY_VERSION")"

mkdir -p "$work"
if [ ! -f "$work/.patched-$version" ]; then
	go mod download "github.com/caddyserver/caddy/v2@$version"
	src="$(go list -m -f '{{.Dir}}' "github.com/caddyserver/caddy/v2@$version")"
	rm -rf "$work/caddy"
	cp -r "$src" "$work/caddy"
	chmod -R u+w "$work/caddy"
	(cd "$work/caddy" && GIT_CEILING_DIRECTORIES="$(dirname "$work")" git apply "$fp/caddy-read-idle-timeout.patch")
	touch "$work/.patched-$version"
fi

cp go.mod "$work/go.mod"
cp go.sum "$work/go.sum"
go mod edit -modfile="$work/go.mod" -require="github.com/caddyserver/caddy/v2@$version" -replace="github.com/caddyserver/caddy/v2=$work/caddy"
CGO_ENABLED=0 go build -modfile="$work/go.mod" -trimpath -ldflags="-s -w" -o "$out" .
