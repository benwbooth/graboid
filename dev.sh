#!/bin/bash
# Development server with auto-reload

PORT=${GRABOID_PORT:-6749}
HOST=${GRABOID_HOST:-0.0.0.0}

echo "Starting Graboid dev server at http://$HOST:$PORT"
echo "Login: admin / adminadmin"
echo ""

# Open browser after short delay
(sleep 2 && xdg-open "http://127.0.0.1:$PORT/jobs" 2>/dev/null) &

uv run python -m uvicorn src.web.app:app --host "$HOST" --port "$PORT" --reload --reload-dir src
