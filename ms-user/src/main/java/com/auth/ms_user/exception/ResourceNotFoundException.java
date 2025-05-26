package com.auth.ms_user.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends BaseControllerException {
    public ResourceNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}
