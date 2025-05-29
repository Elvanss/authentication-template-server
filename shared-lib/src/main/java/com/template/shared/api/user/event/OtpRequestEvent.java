package com.template.shared.api.user.event;
import java.time.Instant;
import java.util.UUID;

import lombok.Data;

@Data
public class OtpRequestEvent {
    
    private UUID userId;
    private String email;
    private Instant timestamp;

    public OtpRequestEvent() {
        this.timestamp = Instant.now();
    }

    public OtpRequestEvent(UUID userId, String email) {
        this.userId = userId;
        this.email = email;
    }

    public UUID getUserId() {
        return userId;
    }
    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

}

