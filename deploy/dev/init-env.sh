#!/usr/bin/env bash
# Creates deploy/.env with random database passwords, or adds any variable a
# newer version needs to an existing file. Existing values are never changed.
set -euo pipefail
env_file="$(dirname "$0")/../.env"
umask 077

random_password() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32; }

if [[ ! -f "$env_file" ]]; then
  cat > "$env_file" <<ENV
ALICE_DB_PASSWORD=$(random_password)
ALICE_APP_DB_PASSWORD=$(random_password)
ALICE_PORT=443
ENV
  echo "Created deploy/.env (mode 600)."
  exit 0
fi

if ! grep -q '^ALICE_APP_DB_PASSWORD=' "$env_file"; then
  echo "ALICE_APP_DB_PASSWORD=$(random_password)" >> "$env_file"
  echo "Added ALICE_APP_DB_PASSWORD to deploy/.env. An existing database volume does not know this role yet: run 'make reset' (deletes local data)."
  exit 0
fi
echo "deploy/.env already exists; keeping it."
