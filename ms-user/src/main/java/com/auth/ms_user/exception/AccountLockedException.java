package com.auth.ms_user.exception;


import org.springframework.http.HttpStatus;

public class AccountLockedException extends RuntimeException {
    private final HttpStatus status;

    public AccountLockedException(String message) {
        super(message);
        this.status = HttpStatus.FORBIDDEN;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
