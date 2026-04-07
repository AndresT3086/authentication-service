-- Tokens de refresco opacos (hash SHA-256); rotación en cada uso; revocación masiva al nuevo login.
CREATE TABLE auth_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX ux_auth_refresh_token_hash ON auth_refresh_tokens (token_hash);
CREATE INDEX idx_auth_refresh_user ON auth_refresh_tokens (user_id);
CREATE INDEX idx_auth_refresh_expires ON auth_refresh_tokens (expires_at);
