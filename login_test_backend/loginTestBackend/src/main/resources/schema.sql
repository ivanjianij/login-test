DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT,
    name            TEXT,
    provider        TEXT NOT NULL CHECK (provider IN ('LOCAL','GOOGLE')),
    oauth_id        TEXT UNIQUE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);