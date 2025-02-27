-- migrate:up
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS seed BIGINT NOT NULL DEFAULT 42;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS device_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS verification_error VARCHAR;

-- migrate:down
ALTER TABLE nodes DROP COLUMN IF EXISTS seed;
ALTER TABLE nodes DROP COLUMN IF EXISTS device_index;
ALTER TABLE nodes DROP COLUMN IF EXISTS verification_error;
