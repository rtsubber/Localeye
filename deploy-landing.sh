#!/bin/bash
# Deploy BrandBoost Studio site to here.now
set -e

API_KEY=$(cat ~/.herenow/credentials)
SLUG=""  # New site, will get assigned
SITE_DIR="/home/ron/.openclaw/workspace/agent-check/landing"

echo "=== Local-Eye API Deploy to here.now ==="
echo "Slug: $SLUG"
echo "Directory: $SITE_DIR"
echo ""

# Collect all files with sizes and content types
declare -A FILES
declare -A CONTENT_TYPES

# Helper to determine content type
content_type() {
    case "$1" in
        *.html) echo "text/html; charset=utf-8" ;;
        *.css)  echo "text/css; charset=utf-8" ;;
        *.js)   echo "text/javascript; charset=utf-8" ;;
        *.png)  echo "image/png" ;;
        *.jpg|*.jpeg) echo "image/jpeg" ;;
        *.gif)  echo "image/gif" ;;
        *.svg)  echo "image/svg+xml" ;;
        *.xml)  echo "application/xml" ;;
        *.txt)  echo "text/plain; charset=utf-8" ;;
        *.json) echo "application/json" ;;
        *.ico)  echo "image/x-icon" ;;
        *)      echo "application/octet-stream" ;;
    esac
}

# Build the file list and compute SHA-256 hashes
FILES_JSON="["
FIRST=true
for f in $(cd "$SITE_DIR" && find . -type f | sort); do
    # Remove leading ./
    path="${f#./}"
    filepath="$SITE_DIR/$path"
    size=$(wc -c < "$filepath")
    hash=$(sha256sum "$filepath" | cut -d' ' -f1)
    ctype=$(content_type "$path")
    
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        FILES_JSON+=","
    fi
    FILES_JSON+="{\"path\":\"$path\",\"size\":$size,\"contentType\":\"$ctype\",\"hash\":\"$hash\"}"
done
FILES_JSON+="]"

echo "Files to deploy:"
echo "$FILES_JSON" | python3 -m json.tool 2>/dev/null || echo "$FILES_JSON"
echo ""

# Step 1: Create the publish request (update existing site)
echo "Step 1: Creating publish request..."
RESPONSE=$(curl -sS -X PUT "https://here.now/api/v1/publish/$SLUG" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"files\":$FILES_JSON}")

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

# Extract finalize URL and version ID
FINALIZE_URL=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['upload']['finalizeUrl'])")
VERSION_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['upload']['versionId'])")

echo ""
echo "Finalize URL: $FINALIZE_URL"
echo "Version ID: $VERSION_ID"
echo ""

# Extract uploads array
UPLOADS_JSON=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['upload']['uploads']))")

# Step 2: Upload each file
echo "Step 2: Uploading files..."
UPLOAD_COUNT=$(echo "$UPLOADS_JSON" | python3 -c "import sys,json; u=json.load(sys.stdin); print(len(u))")

for i in $(seq 0 $((UPLOAD_COUNT-1))); do
    PATH_UP=$(echo "$UPLOADS_JSON" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[$i]['path'])")
    URL_UP=$(echo "$UPLOADS_JSON" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[$i]['url'])")
    CTYPE=$(echo "$UPLOADS_JSON" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[$i]['headers']['Content-Type'])")
    METHOD=$(echo "$UPLOADS_JSON" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[$i].get('method','PUT'))")
    
    FILEPATH="$SITE_DIR/$PATH_UP"
    
    echo "  Uploading: $PATH_UP ($(wc -c < "$FILEPATH") bytes)"
    
    curl -sS -X "$METHOD" "$URL_UP" \
      -H "Content-Type: $CTYPE" \
      --data-binary "@$FILEPATH" > /dev/null
    
    echo "  ✓ Done"
done

# Step 3: Finalize
echo ""
echo "Step 3: Finalizing deployment..."
FINALIZE_RESPONSE=$(curl -sS -X POST "$FINALIZE_URL" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"versionId\":\"$VERSION_ID\"}")

echo "$FINALIZE_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$FINALIZE_RESPONSE"

echo ""
echo "=== Deployment Complete! ==="
echo "Site URL: https://brandbooststudio.co"