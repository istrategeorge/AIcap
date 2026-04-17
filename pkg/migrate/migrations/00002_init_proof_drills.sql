-- Migration: the immutable-ledger tables that back EU AI Act proof drills.
-- Every object uses IF NOT EXISTS so it can be replayed safely against a
-- production DB where the objects were created by hand before the migration
-- runner existed.

CREATE TABLE IF NOT EXISTS projects (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    repository_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS proof_drills (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,

    -- The specific git commit this scan was run against.
    commit_sha VARCHAR(40) NOT NULL,

    -- Raw AI-BOM produced by the Go CLI.
    ai_bom_json JSONB NOT NULL,

    -- Active risk register state / vulnerabilities at scan time.
    risk_register_state JSONB,

    -- Finalized Annex IV markdown — the artefact auditors read.
    annex_iv_markdown TEXT NOT NULL,

    -- Cryptographic hash of the commit, BOM and docs — proves the ledger row
    -- has not been tampered with since it was recorded.
    crypto_hash VARCHAR(64) NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proof_drills_project ON proof_drills(project_id);
CREATE INDEX IF NOT EXISTS idx_proof_drills_commit  ON proof_drills(commit_sha);
