package com.template.shared.api.user.res;

import java.util.UUID;

import lombok.Data;

@Data
public class BlackListTokenResponse {
    private UUID userId;
    private String token;
    private Long expiryDate;

    public BlackListTokenResponse() {}

    public BlackListTokenResponse(UUID userId, String token, Long expiryDate) {
        this.userId = userId;
        this.token = token;
        this.expiryDate = expiryDate;
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
}
