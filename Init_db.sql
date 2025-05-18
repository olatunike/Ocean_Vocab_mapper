-- init_db.sql
-- PostgreSQL database setup for Ocean Vocabulary Mapper

-- Ensure script runs as superuser (e.g., postgres)
-- Create database if it doesn't exist
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ocean_vocabulary_mapper') THEN
      PERFORM dblink_exec('dbname=postgres', 'CREATE DATABASE ocean_vocabulary_mapper');
   END IF;
END
$$;

-- Connect to the database
\c ocean_vocabulary_mapper

-- Create schema for isolation
CREATE SCHEMA IF NOT EXISTS mapper;

-- Set search path to avoid schema prefix in queries
SET search_path TO mapper, public;

-- Create application role with limited privileges
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mapper_app') THEN
      CREATE ROLE mapper_app WITH LOGIN PASSWORD 'secure_password_change_this';
      GRANT CONNECT ON DATABASE ocean_vocabulary_mapper TO mapper_app;
      GRANT USAGE ON SCHEMA mapper TO mapper_app;
   END IF;
END
$$;

-- Create users table
CREATE TABLE mapper.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL CHECK (username ~ '^[a-zA-Z0-9._-]{4,50}$'),
    password TEXT NOT NULL CHECK (length(password) > 0),
    totp_secret TEXT NOT NULL CHECK (length(totp_secret) > 0)
);

-- Create vocabularies table
CREATE TABLE mapper.vocabularies (
    id SERIAL PRIMARY KEY,
    standard VARCHAR(50) NOT NULL CHECK (standard IN ('SeaDataNet', 'CF')),
    term VARCHAR(100) NOT NULL CHECK (term ~ '^[a-zA-Z0-9_ -]+$'),
    description TEXT,
    uri VARCHAR(512),
    UNIQUE (standard, term)
);

-- Create user_mappings table
CREATE TABLE mapper.user_mappings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES mapper.users(id) ON DELETE CASCADE,
    input_term VARCHAR(100) NOT NULL CHECK (input_term ~ '^[a-zA-Z0-9_ -]+$'),
    standard VARCHAR(50) NOT NULL CHECK (standard IN ('SeaDataNet', 'CF')),
    mapped_term VARCHAR(100) NOT NULL CHECK (mapped_term ~ '^[a-zA-Z0-9_ -]+$'),
    uri VARCHAR(512),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant privileges to application role
GRANT SELECT, INSERT, UPDATE, DELETE ON mapper.users TO mapper_app;
GRANT SELECT, INSERT ON mapper.vocabularies TO mapper_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON mapper.user_mappings TO mapper_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA mapper TO mapper_app;

-- Start transaction for data insertion
BEGIN;

-- Insert sample vocabulary data
INSERT INTO mapper.vocabularies (standard, term, description, uri)
VALUES
    ('SeaDataNet', 'TEMP', 'Sea water temperature', 'http://vocab.nerc.ac.uk/collection/P01/current/TEMPPR01/'),
    ('SeaDataNet', 'PSAL', 'Practical salinity', 'http://vocab.nerc.ac.uk/collection/P01/current/PSALST01/'),
    ('CF', 'sea_water_temperature', 'Sea water temperature', 'http://cfconventions.org/Data/cf-standard-names/77/'),
    ('CF', 'sea_water_practical_salinity', 'Practical salinity', 'http://cfconventions.org/Data/cf-standard-names/77/')
ON CONFLICT DO NOTHING;

COMMIT;

-- Create indexes for performance
CREATE INDEX idx_user_mappings_user_id ON mapper.user_mappings(user_id);
CREATE INDEX idx_vocabularies_standard_term ON mapper.vocabularies(standard, term);

-- Revoke unnecessary privileges from public
REVOKE ALL ON DATABASE ocean_vocabulary_mapper FROM PUBLIC;
REVOKE ALL ON SCHEMA mapper FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mapper FROM PUBLIC;
