-- Índice para consultas de auditoría por usuario (reportes / soporte).
CREATE INDEX IF NOT EXISTS idx_security_login_events_user_id ON security_login_events (user_id);
