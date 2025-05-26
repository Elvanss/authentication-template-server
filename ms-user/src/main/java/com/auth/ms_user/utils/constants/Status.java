package com.auth.ms_user.utils.constants;

public enum Status {
    // user status with descriptions
    ACTIVE("Normal functioning account"),
    DISABLED("Admin-disabled, suspended, or frozen account"),
    PENDING_VERIFICATION("Registered but not verified email/phone"),
    LOCKED("Temporarily locked due to failed login attempts"),
    DELETED("Soft-deleted user (data retained, not active)");

    private String status;

    Status(String status) {
        this.status = status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }
}
