-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

-- Key/value application settings. Later phases add secret settings in a sibling table.
CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    secret     boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE settings;
