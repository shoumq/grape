CREATE TABLE IF NOT EXISTS phone_verifications (
    phone TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
