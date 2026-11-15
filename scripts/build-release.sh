#!/usr/bin/env bash
# Cross-compile release binaries, package them, and write SHA-256 checksums
# and a dependency inventory. Usage: scripts/build-release.sh v0.1.0
set -euo pipefail

version="${1:?usage: build-release.sh <version tag>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist"
commit="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
built="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ldflags="-s -w -X main.version=${version#v} -X main.commit=$commit -X main.date=$built"

rm -rf "$out"
mkdir -p "$out"
cd "$root"

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for target in $targets; do
  os="${target%/*}"
  arch="${target#*/}"
  name="agentgov_${version#v}_${os}_${arch}"
  stage="$out/$name"
  mkdir -p "$stage"
  bin="agentgov"
  if [ "$os" = "windows" ]; then bin="agentgov.exe"; fi
  echo "building $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$stage/$bin" ./cmd/agentgov
  cp LICENSE README.md "$stage/"
  if [ -f NOTICE ]; then cp NOTICE "$stage/"; fi
  if [ "$os" = "windows" ] && command -v zip >/dev/null 2>&1; then
    (cd "$out" && zip -q -r "$name.zip" "$name")
  else
    tar -C "$out" -czf "$out/$name.tar.gz" "$name"
  fi
  rm -rf "$stage"
done

# Dependency inventory: every Go module compiled into the binary, with versions.
go list -m -json all > "$out/agentgov_${version#v}_go-modules.json"

(cd "$out" && sha256sum agentgov_* > "agentgov_${version#v}_checksums.txt")
echo "release files:"
ls -1 "$out"
