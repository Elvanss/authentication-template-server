package com.template.shared.api.user.dto;

import java.io.Serializable;
import java.sql.Date;
import java.util.UUID;

public class User implements Serializable {
    private UUID userId;
    private String name;
    private String email;
    private String password;
    private Date dateOfBirth;
    private byte[] profileImage;
    private boolean locked;
    private Integer attemptedCount;

    public User() {
        this.attemptedCount = 0;
    }

    public User(UUID userId, String name, String email, String password, Date dateOfBirth, byte[] profileImage, boolean locked, Integer attemptedCount) {
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.password = password;
        this.dateOfBirth = dateOfBirth;
        this.profileImage = profileImage;
        this.locked = locked;
        this.attemptedCount = attemptedCount != null ? attemptedCount : 0;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Date getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(Date dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public byte[] getProfileImage() {
        return profileImage;
    }

    public void setProfileImage(byte[] profileImage) {
        this.profileImage = profileImage;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public Integer getAttemptedCount() {
        return attemptedCount;
    }

    public void setAttemptedCount(Integer attemptedCount) {
        this.attemptedCount = attemptedCount;
    }
}
