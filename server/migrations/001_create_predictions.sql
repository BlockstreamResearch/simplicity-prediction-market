CREATE TABLE IF NOT EXISTS predictions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    deadline BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    resolution_occurred_at BIGINT,
    resolution_signature TEXT,
    CHECK ((resolution_occurred_at IS NULL) = (resolution_signature IS NULL))
);

CREATE TABLE IF NOT EXISTS price_markets (
    prediction_id TEXT PRIMARY KEY REFERENCES predictions(id) ON DELETE CASCADE,
    feed_id BIGINT NOT NULL,
    decimals BIGINT NOT NULL,
    strike TEXT NOT NULL,
    above INTEGER NOT NULL CHECK (above IN (0, 1)),
    opens_at BIGINT NOT NULL,
    claim_grace BIGINT NOT NULL,
    house_script_pubkey TEXT NOT NULL,
    tick_asset_id TEXT NOT NULL,
    verifier_asset_id TEXT NOT NULL,
    storm_eye_asset_id TEXT NOT NULL
);
