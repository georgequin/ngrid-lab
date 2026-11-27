-- =============================================================================
--  Seed data for the nibbs-api-lab ledger.
--  Intentionally simple and insecure (plaintext-ish, predictable IDs) so the
--  injection / IDOR exercises have something to find. Local lab use only.
-- =============================================================================

CREATE TABLE IF NOT EXISTS accounts (
    id            BIGINT PRIMARY KEY,
    owner_sub     TEXT        NOT NULL,
    currency      CHAR(3)     NOT NULL DEFAULT 'NGN',
    balance_minor BIGINT      NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transfers (
    id           BIGSERIAL PRIMARY KEY,
    from_account BIGINT      NOT NULL,
    to_account   BIGINT      NOT NULL,
    amount_minor BIGINT      NOT NULL,
    memo         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A "secrets" table to make SQL-injection impact obvious (UNION target).
CREATE TABLE IF NOT EXISTS api_keys (
    id        BIGSERIAL PRIMARY KEY,
    label     TEXT NOT NULL,
    secret    TEXT NOT NULL,
    scope     TEXT NOT NULL
);

INSERT INTO accounts (id, owner_sub, currency, balance_minor) VALUES
    (1001, 'alice',          'NGN', 2500000),
    (1002, 'bob',            'NGN',  180000),
    (1003, 'carol',          'USD',   90000),
    (1004, 'david',          'NGN', 1250000),
    (1005, 'ngozi',          'NGN',  640000),
    (1006, 'tunde',          'NGN',   45000),
    (1007, 'amaka',          'USD',  120000),
    (9001, 'internal-system','NGN', 999999999)
ON CONFLICT (id) DO NOTHING;

INSERT INTO transfers (from_account, to_account, amount_minor, memo) VALUES
    (1001, 1002,  50000, 'rent split'),
    (1002, 1003,  12000, 'lunch'),
    (9001, 1001, 500000, 'settlement:batch-0001');

INSERT INTO api_keys (label, secret, scope) VALUES
    ('settlement-signer', 'sk_lab_7f3c9a2e_do_not_reuse', 'settlement:write'),
    ('reporting-readonly', 'sk_lab_11b4_report_only',      'reports:read');
