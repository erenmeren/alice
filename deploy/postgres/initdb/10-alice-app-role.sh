#!/bin/sh
# Runs once, when PostgreSQL initialises an empty data volume. Creates the
# application login role; migrations (run as the owner) grant its privileges.
# The password comes from the environment and is quoted by psql (:'app_pw').
set -eu
: "${ALICE_APP_DB_PASSWORD:?ALICE_APP_DB_PASSWORD is not set}"
psql -v ON_ERROR_STOP=1 -v app_pw="$ALICE_APP_DB_PASSWORD" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE alice_app LOGIN PASSWORD :'app_pw';
SQL
