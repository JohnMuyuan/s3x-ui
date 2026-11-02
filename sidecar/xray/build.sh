#!/bin/sh
# Builds Xray for linux with reality-keyshare.patch, and puts its LICENSE next
# to the binary. Usage: ./build.sh <amd64|arm64> [output]
set -e
ARCH="${1:?usage: build.sh <amd64|arm64> [output]}"
OUT="${2:-xray-linux-$ARCH}"
XRAY_VERSION=v26.10.21
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK"; rm -rf "$WORK"' EXIT

git clone --quiet --depth 1 --branch "$XRAY_VERSION" https://github.com/XTLS/Xray-core.git "$WORK/xray"
cd "$WORK/xray"
REALITY="$(go mod download -json github.com/xtls/reality | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
cp -r "$REALITY" "$WORK/reality"
chmod -R u+w "$WORK/reality"
patch --quiet --directory="$WORK/reality" -p1 < "$HERE/reality-keyshare.patch"
go mod edit -replace "github.com/xtls/reality=../reality"
COMMIT="$(git rev-parse --short HEAD)"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -mod=mod -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X github.com/xtls/xray-core/core.build=$COMMIT-s3x" -o "$OUT" ./main
cp LICENSE "$(dirname "$OUT")/LICENSE"
