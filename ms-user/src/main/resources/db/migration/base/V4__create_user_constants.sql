
ALTER TABLE "user_settings"
ADD COLUMN role VARCHAR(30) NOT NULL DEFAULT 'ROLE_USER';


ALTER TABLE "user_settings"
ADD CONSTRAINT status_check
CHECK (status IN ('ACTIVE', 'DISABLED', 'PENDING_VERIFICATION', 'LOCKED', 'DELETED'));

-- Add check constraint for role
ALTER TABLE "user_settings"
ADD CONSTRAINT role_check
CHECK (role IN ('ROLE_TESTER', 'ROLE_USER', 'ROLE_ARTIST', 'ROLE_ADMIN'));