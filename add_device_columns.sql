ALTER TABLE users ADD COLUMN IF NOT EXISTS device_primary VARCHAR(128);
ALTER TABLE users ADD COLUMN IF NOT EXISTS device_secondary VARCHAR(128);
CREATE INDEX IF NOT EXISTS idx_users_device_primary ON users (device_primary);
CREATE INDEX IF NOT EXISTS idx_users_device_secondary ON users (device_secondary);

