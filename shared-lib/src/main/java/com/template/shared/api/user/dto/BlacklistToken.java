package com.template.shared.api.user.dto;

import java.util.UUID;

public class BlacklistToken {
    private UUID tokenId;
    private UUID userId;
    private String token;
    private Long expiryDate;
    private Long createdAt;
    private Long updatedAt; 

    public BlacklistToken() {}

    public BlacklistToken(UUID tokenId, UUID userId, String token, Long expiryDate, Long createdAt, Long updatedAt) {
        this.tokenId = tokenId;
        this.userId = userId;
        this.token = token;
        this.expiryDate = expiryDate;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public UUID getTokenId() {
        return tokenId;
    }
    public void setTokenId(UUID tokenId) {
        this.tokenId = tokenId;
    }
    public UUID getUserId() {
        return userId;
    }
    public void setUserId(UUID userId) {
        this.userId = userId;
    }
    public String getToken() {
        return token;
    }
    public void setToken(String token) {
        this.token = token;
    }
    public Long getExpiryDate() {
        return expiryDate;
    }
    public void setExpiryDate(Long expiryDate) {
        this.expiryDate = expiryDate;
    }
    public Long getCreatedAt() {
        return createdAt;
    }
    public void setCreatedAt(Long createdAt) {
        this.createdAt = createdAt;
    }
    public Long getUpdatedAt() {
        return updatedAt;
    }
    public void setUpdatedAt(Long updatedAt) {
        this.updatedAt = updatedAt;
    }
}
