-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

-- Key/value application settings. Rows with secret = true hold sensitive values.
CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    secret     boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE settings;
