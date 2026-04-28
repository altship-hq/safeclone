#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
docker build -t safeclone-scanner:latest "$SCRIPT_DIR"
echo "built safeclone-scanner:latest"
