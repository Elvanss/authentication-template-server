package com.auth.ms_notification.application;

public interface ITokenService {
    String generateResetToken(String email);
    boolean validateResetToken(String token, String email);
}
