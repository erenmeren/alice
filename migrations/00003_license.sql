-- +goose Up
-- Phase 2: licensing (spec §7.6, §16; R36) and the notification outbox (§7.6, R11).

-- The installation: its ID and timestamp (the 30-day evaluation runs from installed_at and a
-- restore keeps both), the cached license state (recomputed from the files, never trusted over
-- them) and a held forward clock jump that must survive a restart (R26).
CREATE TABLE license (
    id              smallint PRIMARY KEY CHECK (id = 1),
    installation_id text NOT NULL,
    installed_at    timestamptz NOT NULL,
    state           text NOT NULL CHECK (state IN ('evaluation', 'evaluation_expired', 'active', 'grace', 'locked')),
    clock_jump      jsonb,
    updated_at      timestamptz NOT NULL
);

-- Every accepted upload, verbatim. Parsed values are never stored: they are re-verified from
-- raw_file at every evaluation, so editing a row cannot change a license (L-49).
CREATE TABLE license_files (
    id          uuid PRIMARY KEY,
    seq         bigint NOT NULL UNIQUE CHECK (seq > 0),
    sha256      bytea NOT NULL UNIQUE,
    raw_file    bytea NOT NULL CHECK (octet_length(raw_file) BETWEEN 1 AND 65536),
    uploaded_at timestamptz NOT NULL,
    uploaded_by uuid REFERENCES users (id)
);

-- Status history (spec §7.6 "license_history"). A notice (a warning email, a grace day, the
-- lock, a clock anomaly of one day) is recorded once per license: the unique index is what makes
-- warnings exactly-once across restarts and concurrent evaluations (L-14).
CREATE TABLE license_history (
    id         uuid PRIMARY KEY,
    at         timestamptz NOT NULL,
    event      text NOT NULL CHECK (event IN ('installed', 'renewed', 'state_change', 'clock_anomaly', 'rejected', 'notice')),
    license_id text NOT NULL DEFAULT '',
    from_state text NOT NULL DEFAULT '',
    to_state   text NOT NULL DEFAULT '',
    notice     text,
    details    jsonb NOT NULL DEFAULT '{}',
    CONSTRAINT license_history_notice_key CHECK ((event = 'notice') = (notice IS NOT NULL))
);
CREATE UNIQUE INDEX license_history_notice_once ON license_history (license_id, notice) WHERE event = 'notice';
CREATE INDEX license_history_at ON license_history (at DESC, id DESC);

-- Emails waiting to be sent; drained by the notify.send job so mail failures never block work.
CREATE TABLE notifications_outbox (
    id              uuid PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('email')),
    to_address      text NOT NULL,
    template_key    text NOT NULL,
    params          jsonb NOT NULL DEFAULT '{}',
    locale          text NOT NULL,
    status          text NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'skipped_no_smtp')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    sent_at         timestamptz,
    last_error_code text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL
);
CREATE INDEX notifications_outbox_due ON notifications_outbox (next_attempt_at) WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE ON license TO alice_app;
GRANT SELECT, INSERT ON license_files, license_history TO alice_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON notifications_outbox TO alice_app;

-- +goose Down
DROP TABLE notifications_outbox;
DROP TABLE license_history;
DROP TABLE license_files;
DROP TABLE license;
