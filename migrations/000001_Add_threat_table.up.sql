CREATE TABLE IF NOT EXISTS threats (
    md5 TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT threat_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);
