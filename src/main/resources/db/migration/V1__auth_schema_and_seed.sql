-- Esquema propio del microservicio de autenticación (BD dedicada).
-- Índices para búsqueda por correo (login) y auditoría por tiempo.

CREATE TABLE auth_roles (
    id UUID PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE auth_users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_users_email_lower ON auth_users (LOWER(email));

CREATE TABLE auth_user_roles (
    user_id UUID NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES auth_roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE security_login_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    email VARCHAR(255) NOT NULL,
    success BOOLEAN NOT NULL,
    reason VARCHAR(500),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_security_login_events_email ON security_login_events (email);
CREATE INDEX idx_security_login_events_occurred ON security_login_events (occurred_at);

-- Procedimiento almacenado: centraliza inserción de auditoría de intentos de login.
CREATE OR REPLACE PROCEDURE sp_log_login_event(
    IN p_user_id UUID,
    IN p_email VARCHAR(255),
    IN p_success BOOLEAN,
    IN p_reason VARCHAR(500)
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO security_login_events (user_id, email, success, reason)
    VALUES (p_user_id, p_email, p_success, p_reason);
END;
$$;

-- Datos semilla: admin@logistics.com / password  (BCrypt, coste 10 — compatible con verificación BCrypt)
INSERT INTO auth_roles (id, name) VALUES
    ('11111111-1111-1111-1111-111111111111', 'ROLE_ADMIN'),
    ('22222222-2222-2222-2222-222222222222', 'ROLE_OPERATOR');

INSERT INTO auth_users (id, email, password_hash, enabled, failed_login_attempts, created_at, updated_at)
VALUES (
    '33333333-3333-3333-3333-333333333333',
    'admin@logistics.com',
    '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG',
    TRUE,
    0,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT INTO auth_user_roles (user_id, role_id) VALUES
    ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111');
