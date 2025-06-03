package com.auth.ms_notification.application;

public interface INotificationService {

    // Send an email with a verification code
    void sendOtpEmail(String email, Integer otp);

    void sendResetPasswordEmail(String email, String resetToken);

    // Send an email with locked account notification
    void sendLockedAccountEmail(String email);
}
