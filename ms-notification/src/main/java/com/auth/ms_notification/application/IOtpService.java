package com.auth.ms_notification.application;

public interface IOtpService {
    Integer generateOtp(String email);
    boolean verifyOtp(String email, Integer inputOtp);
    void deleteOtp(String email);
}