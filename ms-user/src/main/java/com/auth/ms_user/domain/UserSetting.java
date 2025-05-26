package com.auth.ms_user.domain;

import java.time.LocalDateTime;
import java.util.UUID;

import com.auth.ms_user.utils.constants.Status;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "\"user_settings\"")
public class UserSetting {

    @Id
    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;

    @Column(name = "is_email_verified", nullable = false)
    private boolean isEmailVerified = false;

    @Column(name = "is_phone_verified", nullable = false)
    private boolean isPhoneVerified = false;

    @Column(name = "is_account_locked", nullable = false)
    private boolean isAccountLocked = false;

    @Column(name = "language", length = 50)
    private String language;

    @Column(name = "dark_mode", nullable = false)
    private boolean darkMode = true;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    @Column(name = "status", nullable = false)
    @Enumerated
    (
        value = jakarta.persistence.EnumType.STRING
    )
    private Status status;
}