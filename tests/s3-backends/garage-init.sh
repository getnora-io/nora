#!/bin/sh
set -e

apk add --no-cache curl jq >/dev/null 2>&1

ADMIN=http://garage:3903
AUTH="Authorization: Bearer testtoken"
CT="Content-Type: application/json"

sleep 2

# Get node ID
NODE_ID=$(curl -sf -H "$AUTH" "$ADMIN/v1/status" | jq -r '.node')
echo "Node ID: $NODE_ID"

# Assign layout
curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/layout" \
  -d "[{\"id\":\"$NODE_ID\",\"zone\":\"dc1\",\"capacity\":1073741824,\"tags\":[]}]"

# Get next layout version
LAYOUT_VER=$(curl -sf -H "$AUTH" "$ADMIN/v1/layout" | jq '.version + 1')
echo "Layout version: $LAYOUT_VER"

# Apply layout
curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/layout/apply" \
  -d "{\"version\":$LAYOUT_VER}"

# Create key and capture credentials
KEY_RESP=$(curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/key" \
  -d '{"name":"nora-test-key"}')
KEY_ID=$(echo "$KEY_RESP" | jq -r '.accessKeyId')
KEY_SECRET=$(echo "$KEY_RESP" | jq -r '.secretAccessKey')
echo "Key ID: $KEY_ID"

# Export credentials for nora-garage and s3-tools via shared volume
if [ -d /creds ]; then
  cat > /creds/env <<EOF
export NORA_STORAGE_S3_ACCESS_KEY="${KEY_ID}"
export NORA_STORAGE_S3_SECRET_KEY="${KEY_SECRET}"
export GARAGE_ACCESS_KEY="${KEY_ID}"
export GARAGE_SECRET_KEY="${KEY_SECRET}"
EOF
  echo "Credentials written to /creds/env"
fi

# Create bucket and capture bucket ID
BUCKET_RESP=$(curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/bucket" \
  -d '{"globalAlias":"nora-test"}')
BUCKET_ID=$(echo "$BUCKET_RESP" | jq -r '.id')
echo "Bucket ID: $BUCKET_ID"

# Allow key on bucket
curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/bucket/allow" \
  -d "{\"bucketId\":\"$BUCKET_ID\",\"accessKeyId\":\"$KEY_ID\",\"permissions\":{\"read\":true,\"write\":true,\"owner\":true}}"

echo "Garage init complete"
