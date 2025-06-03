package com.auth.ms_notification.application.Impl;

import java.security.SecureRandom;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.auth.ms_notification.application.IOtpService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService implements IOtpService {

    private final RedisTemplate<String, Integer> redisTemplate;
    private static final SecureRandom random = new SecureRandom();

    @Value("${otp.expiration.minutes:5}")
    private int otpExpirationMinutes;

    @Override
    @Transactional
    public Integer generateOtp(String email) {
        // Delete any existing OTP for the email
        deleteOtp(email);
        Integer otp = random.nextInt(900000) + 100000;
        redisTemplate.opsForValue().set("otpGenerated:" + email, otp, Duration.ofMinutes(otpExpirationMinutes));
        log.info("Generated OTP for {}: {}", email, otp);
        return otp;
    }

    @Override
    public boolean verifyOtp(String email, Integer inputOtp) {
        Integer otp = redisTemplate.opsForValue().get("otpGenerated:" + email);
        return otp != null && inputOtp.equals(otp);
    }

    @Override
    public void deleteOtp(String email) {
        redisTemplate.delete("otpGenerated:" + email);
        log.info("Deleted OTP for {}", email);
    }
}
