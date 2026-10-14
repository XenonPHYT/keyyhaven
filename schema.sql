-- ============================================================
-- Keyy's Haven — Cloudflare D1 (SQLite) relational schema
-- Apply with:  npx wrangler d1 execute keyys-haven-db --remote --file=schema.sql
-- (D1 enforces referential integrity natively; no PRAGMA needed)
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
  id                 TEXT PRIMARY KEY,                       -- internal UUID — NEVER exposed to the public DOM
  username           TEXT NOT NULL,
  username_lower     TEXT NOT NULL UNIQUE,                   -- case-insensitive lookup handle
  password_hash      TEXT NOT NULL,                          -- pbkdf2$iterations$saltB64url$hashB64url
  secret_question    TEXT NOT NULL,
  secret_answer_hash TEXT NOT NULL,                          -- hashed, never plaintext
  pin_hash           TEXT NOT NULL,                          -- 6-digit recovery PIN, stored hashed
  is_verified        INTEGER NOT NULL DEFAULT 0 CHECK (is_verified IN (0, 1)),  -- master switch: 0 = member, 1 = verified badge
  private_token      TEXT NOT NULL UNIQUE,                   -- hidden node token, disclosed only to the true account holder
  flagged_count      INTEGER NOT NULL DEFAULT 0,             -- running count of flagged comment patterns
  created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_posts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  author_key  TEXT NOT NULL CHECK (author_key IN ('keyy', 'platform')),  -- only two posting authorities exist
  body        TEXT NOT NULL,
  media_json  TEXT NOT NULL DEFAULT '[]',                    -- text-serialized JSON array of R2 WebP paths
  pinned      INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_order ON feed_posts (pinned DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS comments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id     INTEGER NOT NULL REFERENCES feed_posts(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted_by_admin')),  -- soft-delete flag
  flagged     INTEGER NOT NULL DEFAULT 0 CHECK (flagged IN (0, 1)),
  flag_reason TEXT,                                          -- which admin-tracked pattern tripped (nullable)
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments (post_id, status);
CREATE INDEX IF NOT EXISTS idx_comments_flag ON comments (flagged, status);

-- Single-pass emoji reactions: one reaction per user per post.
-- Re-tapping a different emoji switches it; re-tapping the same one clears it.
CREATE TABLE IF NOT EXISTS reactions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id    INTEGER NOT NULL REFERENCES feed_posts(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  emoji      TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (post_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,                               -- opaque random session token (cookie value)
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Temporary shareable crypto-hashes mapped to specific timeline post blocks
CREATE TABLE IF NOT EXISTS share_tokens (
  token_hash TEXT PRIMARY KEY,                               -- short-lived cryptographic hash (share path suffix)
  post_id    INTEGER NOT NULL REFERENCES feed_posts(id) ON DELETE CASCADE,
  created_by TEXT,                                          -- internal user id of the sharer (footprint kept server-side only)
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_share_expiry ON share_tokens (expires_at);

-- Failure counters for login / PIN recovery / admin-key rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
  key      TEXT PRIMARY KEY,
  count    INTEGER NOT NULL,
  reset_at INTEGER NOT NULL                                  -- epoch ms
);

CREATE TABLE IF NOT EXISTS site_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- ------------------------------------------------------------
-- Seed data
-- ------------------------------------------------------------
INSERT OR IGNORE INTO site_settings (key, value) VALUES
  ('live_stream', '0'),
  ('live_expires_at', '0'),
  ('share_ttl_minutes', '15');

INSERT INTO feed_posts (author_key, body, media_json, pinned, created_at)
SELECT * FROM (
  SELECT 'keyy' AS a, 'Welcome to Keyy''s Haven — the official timeline. Everything I stream, build and ship lands right here first. 🏰' AS b, '[]' AS c, 1 AS d, '2026-01-01T00:00:00.000Z' AS e
  UNION ALL
  SELECT 'platform', 'System broadcast: timeline engine online. Comment and reaction pipelines are live.', '[]', 0, '2026-01-01T00:05:00.000Z'
) WHERE NOT EXISTS (SELECT 1 FROM feed_posts);
