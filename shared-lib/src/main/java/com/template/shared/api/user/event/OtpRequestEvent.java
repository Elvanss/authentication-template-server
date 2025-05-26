package com.template.shared.api.user.event;
import java.time.Instant;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpRequestEvent {
    private UUID userId;
    private String email;
    private Instant timestamp;

    public OtpRequestEvent(UUID userId, String email) {
        this.userId = userId;
        this.email = email;
    }
}

