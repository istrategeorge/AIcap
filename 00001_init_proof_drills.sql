-- Create Projects Table
CREATE TABLE projects (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    repository_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Proof Drills Table (Immutable Ledger for EU AI Act compliance)
CREATE TABLE proof_drills (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    
    -- The specific git commit this scan was run against
    commit_sha VARCHAR(40) NOT NULL,
    
    -- Store the generated AI-BOM from the Go CLI
    ai_bom_json JSONB NOT NULL,
    
    -- Store the active risk register state/vulnerabilities
    risk_register_state JSONB,
    
    -- Store the finalized Annex IV markdown documentation
    annex_iv_markdown TEXT NOT NULL,
    
    -- Cryptographic hash of the commit, BOM, and docs for immutable proof
    crypto_hash VARCHAR(64) NOT NULL,
    
    -- Timestamp for when the proof drill was recorded
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Indexes for fast querying by auditors
CREATE INDEX idx_proof_drills_project ON proof_drills(project_id);
CREATE INDEX idx_proof_drills_commit ON proof_drills(commit_sha);

-- Add Row Level Security (RLS) policies (Supabase best practice)
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE proof_drills ENABLE ROW LEVEL SECURITY;