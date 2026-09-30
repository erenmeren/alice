#!/usr/bin/env bash
# Creates deploy/.env with a random database password if it does not exist yet.
set -euo pipefail
env_file="$(dirname "$0")/../.env"
if [[ -f "$env_file" ]]; then
  echo "deploy/.env already exists; keeping it."
  exit 0
fi
umask 077
password="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32)"
cat > "$env_file" <<ENV
ALICE_DB_PASSWORD=${password}
ALICE_PORT=443
ENV
echo "Created deploy/.env (mode 600)."
