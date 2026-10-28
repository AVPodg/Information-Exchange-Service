ALTER TABLE threats DROP CONSTRAINT threat_severity;

ALTER TABLE threats ADD CONSTRAINT threat_severity
    CHECK (severity IN ('low', 'medium', 'high', 'critical'));
