package com.auth.ms_user.utils.constants;

public enum Role {
    TESTER("ROLE_TESTER"),
    USER("ROLE_USER"),
    ARTIST("ROLE_ARTIST"),
    ADMIN("ROLE_ADMIN");

    private String role;

    Role(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
