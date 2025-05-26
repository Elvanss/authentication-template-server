package com.auth.ms_user.exception;

import org.springframework.http.HttpStatus;

public class InvalidInputException extends BaseControllerException {
    public InvalidInputException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
