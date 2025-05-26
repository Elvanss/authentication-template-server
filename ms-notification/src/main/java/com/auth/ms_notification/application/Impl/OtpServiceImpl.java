package com.auth.ms_notification.application.Impl;

import java.security.SecureRandom;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.auth.ms_notification.application.IOtpService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements IOtpService {

    private final RedisTemplate<String, Integer> redisTemplate;
    private static final SecureRandom random = new SecureRandom();

    @Value("${otp.expiration.minutes:5}")
    private int otpExpirationMinutes;

    @Override
    public Integer generateOtp(String email) {
        Integer otp = random.nextInt(900000) + 100000;
        redisTemplate.opsForValue().set(email, otp, Duration.ofMinutes(otpExpirationMinutes));
        log.info("Generated OTP for {}: {}", email, otp);
        return otp;
    }

    @Override
    // Not available if using Redis
    // @Cacheable(value = "otpCache", key = "#email")
    public boolean verifyOtp(String email, Integer inputOtp) {
        Integer otp = redisTemplate.opsForValue().get(email);
        return otp != null && inputOtp.equals(otp);
    }

    @Override
    // Not available if using Redis
    // @CacheEvict(value = "otpCache", key = "#email")
    public void deleteOtp(String email) {
        redisTemplate.delete(email);
        log.info("Deleted OTP for {}", email);
    }
}