#!/usr/bin/env bash
# Verify the SHA-256 checksums of release files. Usage: scripts/verify-release.sh dist
set -euo pipefail
dir="${1:-dist}"
cd "$dir"
file="$(ls agentgov_*_checksums.txt | head -n 1)"
sha256sum -c "$file"
echo "all checksums match"
