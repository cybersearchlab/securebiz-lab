-- database/init/001-extension.sql

-- Activate the pgsodium extension.
-- This extension provides cryptographic functions, including Ed25519 
-- signature verification, which are required for validating the context 
-- signed by Vault Transit.
CREATE EXTENSION IF NOT EXISTS pgsodium;