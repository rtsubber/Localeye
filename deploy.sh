#!/bin/bash
set -e

API_KEY=$(cat ~/.herenow/credentials)
SLUG=""  # Will be set after first deploy
SITE_DIR="/home/ron/.openclaw/workspace/agent-check/landing"

# For now, let's use curl directly
echo "Deploying Local-Eye API landing page..."

# Read index.html content
INDEX_CONTENT=$(cat "$SITE_DIR/index.html")

# Create publish request
RESP=$(curl -s -X POST "https://api.here.now/v1/publish" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"files\": {\"index.html\": {\"contentType\": \"text/html; charset=utf-8\"}}}")

echo "$RESP"
