#!/bin/sh
# Builds sbcore for linux. Usage: ./build.sh <amd64|arm64> [output]
set -e
cd "$(dirname "$0")"
ARCH="${1:?usage: build.sh <amd64|arm64> [output]}"
OUT="${2:-sbcore-linux-$ARCH}"
SB_VERSION=$(go list -m -f '{{.Version}}' github.com/sagernet/sing-box | sed 's/^v//')
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -tags with_quic,with_utls -trimpath \
  -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=$SB_VERSION" -o "$OUT" .
