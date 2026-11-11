CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  mfa_enabled boolean NOT NULL DEFAULT false,
  mfa_secret_encrypted text,
  mfa_pending_secret_encrypted text,
  mfa_pending_expires_at timestamptz,
  mfa_recovery_code_hashes text[] NOT NULL DEFAULT ARRAY[]::text[],
  mfa_last_counter bigint NOT NULL DEFAULT -1,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_encrypted text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_secret_encrypted text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_expires_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_code_hashes text[] NOT NULL DEFAULT ARRAY[]::text[];
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_counter bigint NOT NULL DEFAULT -1;

CREATE TABLE IF NOT EXISTS workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS memberships (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'admin', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash char(64) PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS mfa_login_challenges (
  challenge_hash char(64) PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mfa_login_challenges_expiry_idx ON mfa_login_challenges(expires_at);

CREATE TABLE IF NOT EXISTS runs (
  run_id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  scenario text,
  trace text NOT NULL DEFAULT '',
  outcome text NOT NULL,
  source text NOT NULL,
  repaired boolean NOT NULL DEFAULT false,
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS runs_workspace_created_idx ON runs(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS paypal_webhook_events (
  event_id text PRIMARY KEY,
  workspace_id uuid REFERENCES workspaces(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  order_id text,
  resource_id text,
  resource_status text,
  deliveries integer NOT NULL DEFAULT 1 CHECK (deliveries > 0),
  first_received_at timestamptz NOT NULL DEFAULT now(),
  last_received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS paypal_webhook_workspace_received_idx ON paypal_webhook_events(workspace_id, last_received_at DESC);

-- A database belongs to exactly one PayPal environment. Sandbox and Live
-- deployments must use separate databases to prevent mixed payment histories.
CREATE TABLE IF NOT EXISTS paypal_environment_lock (
  id smallint PRIMARY KEY CHECK (id = 1),
  paypal_environment text NOT NULL CHECK (paypal_environment IN ('sandbox', 'live')),
  locked_at timestamptz NOT NULL DEFAULT now()
);
