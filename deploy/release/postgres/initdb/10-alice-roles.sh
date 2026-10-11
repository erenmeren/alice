#!/bin/sh
# Alice production roles (R43 row 7): a non-superuser owner for migrations and restores, the application role, and the
# database. Runs once, as the postgres image initialises an empty data directory.
set -eu
# The passwords never enter an argument list (S-20): psql reads the secret files itself.
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
\set owner_pw `cat /run/secrets/db_owner_password`
\set app_pw `cat /run/secrets/db_app_password`
CREATE ROLE alice_owner LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD :'owner_pw';
CREATE ROLE alice_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_pw';
GRANT SET ON PARAMETER session_replication_role TO alice_owner;
CREATE DATABASE alice OWNER alice_owner;
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname alice <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO alice_owner;
SQL
