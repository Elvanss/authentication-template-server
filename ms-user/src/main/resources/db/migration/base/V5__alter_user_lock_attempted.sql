ALTER TABLE "users" 
    ADD account_locked BOOLEAN default true,
    ADD attempted_count INT DEFAULT 0;