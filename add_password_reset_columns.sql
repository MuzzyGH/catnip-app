-- Add password reset columns to users table
-- PostgreSQL uses TIMESTAMP, not datetime

-- Check if columns already exist before adding
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='password_reset_token') THEN
        ALTER TABLE users ADD COLUMN password_reset_token VARCHAR(100) UNIQUE;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='password_reset_sent_at') THEN
        ALTER TABLE users ADD COLUMN password_reset_sent_at TIMESTAMP;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='password_reset_expires_at') THEN
        ALTER TABLE users ADD COLUMN password_reset_expires_at TIMESTAMP;
    END IF;
END $$;


