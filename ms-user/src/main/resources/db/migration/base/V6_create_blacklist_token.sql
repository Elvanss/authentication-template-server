CREATE TABLE blacklist_token (
    blacklist_token_id UUID PRIMARY KEY,
    user_id UUID PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    expire_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
);

--  Index for optimizing queries on token and user_id
CREATE INDEX idx_blacklist_token_user_id ON blacklist_token (token, user_id);`