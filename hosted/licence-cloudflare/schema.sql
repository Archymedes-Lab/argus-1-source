-- D1 schema for pay.archymedes.xyz (src/index.ts). Idempotent: safe to run again.
-- Times are unix seconds. No email address is stored: the receipt email is read from the
-- Stripe event when the key is mailed, and never written here or to logs.

CREATE TABLE IF NOT EXISTS licences (
  key            TEXT PRIMARY KEY,                 -- ARGUS-<SERVER|DESKTOP>-<UUID v4 upper-case>
  session_id     TEXT NOT NULL UNIQUE,             -- the Checkout Session: same session, same key
  offer          TEXT NOT NULL,                    -- argus-server | argus-desktop
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  expires_at     INTEGER,                          -- null = no fixed end
  customer       TEXT,                             -- cus_… (billing portal)
  subscription   TEXT,                             -- sub_… (subscription offers)
  payment_intent TEXT,                             -- pi_… (one-time offers; refunds; none sold now)
  livemode       INTEGER NOT NULL DEFAULT 0,
  ref            TEXT,                             -- attribution ref from /buy, if any
  emailed_at     INTEGER,                          -- set once the key email went out
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS licences_subscription ON licences (subscription);
CREATE INDEX IF NOT EXISTS licences_payment_intent ON licences (payment_intent);

-- One activation per key; the label is the server's (or computer's) name.
CREATE TABLE IF NOT EXISTS activations (
  id                TEXT PRIMARY KEY,
  key               TEXT NOT NULL UNIQUE REFERENCES licences (key),
  label             TEXT NOT NULL,
  created_at        INTEGER NOT NULL,
  last_validated_at INTEGER
);

-- Stripe event ids already handled (webhook idempotency).
CREATE TABLE IF NOT EXISTS processed_events (
  id           TEXT PRIMARY KEY,
  type         TEXT NOT NULL,
  processed_at INTEGER NOT NULL
);
