-- +goose Up
-- Hardening batch 1, D3 (R64 Ruling 12): a notice an incident sends once (the Windows store notice "a compromised
-- certificate is still in the machine store") is recorded here, keyed by the incident and the notice, so two cleanup jobs
-- at the same moment, or a repeat after the outbox's retention pruning, never send it twice. The notice names its kind
-- and its object: 'windows.compromised_in_store:<thumbprint>'. Rows are history: the application inserts and reads them.
CREATE TABLE incident_notices (
    incident_id uuid NOT NULL REFERENCES certificate_incidents (id),
    notice      text NOT NULL CHECK (notice ~ '^[a-z0-9_.]+:[0-9A-Fa-f]{40}$'),
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (incident_id, notice)
);
GRANT SELECT, INSERT ON incident_notices TO alice_app;

-- The store notices already queued (those the outbox still holds) are recorded, so an update does not send them again.
INSERT INTO incident_notices (incident_id, notice, created_at)
SELECT (o.params->>'incident_id')::uuid, 'windows.compromised_in_store:' || lower(o.params->>'thumbprint'), min(o.created_at)
FROM notifications_outbox o
WHERE o.template_key = 'windows.compromised_in_store'
  AND o.params->>'incident_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND o.params->>'thumbprint' ~ '^[0-9A-Fa-f]{40}$'
  AND EXISTS (SELECT 1 FROM certificate_incidents i WHERE i.id::text = o.params->>'incident_id')
GROUP BY 1, 2
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE incident_notices;
