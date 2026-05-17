-- Храним SHA-256(raw_token), не сам токен.
-- Даже если дампнут БД — хэши бесполезны без оригинальных токенов.
--
-- Rotation: при каждом /refresh-token старая строка удаляется атомарно
-- через DELETE ... RETURNING, новая вставляется. Один токен = одно использование.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INT         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rt_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens(expires_at);