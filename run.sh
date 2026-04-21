#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

cd "$BACKEND_DIR"

exec ./venv/bin/uvicorn main:app --host "$HOST" --port "$PORT" --reload