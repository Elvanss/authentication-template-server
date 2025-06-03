package com.auth.ms_notification.application.Impl;

import java.time.Duration;
import java.util.UUID;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.auth.ms_notification.application.ITokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService implements ITokenService{
    
    private final RedisTemplate<String, String> redisTemplate;
    @Override
    public String generateResetToken(String email) {
        String resetToken = UUID.randomUUID().toString();

        // Store token in Redis
        redisTemplate.opsForValue().set(
            "resetToken:" + resetToken,
            email,
            Duration.ofMinutes(15)
        );
        return resetToken;
    }

    @Override
    public boolean validateResetToken(String token, String email) {
        String storedEmail = redisTemplate.opsForValue().get("resetToken:" + token);
        
        if (storedEmail == null) {
            log.warn("Invalid reset token: {}", token);
            return false;
        }

        if (!storedEmail.equals(email)) {
            log.warn("Reset token does not match email: {} != {}", storedEmail, email);
            return false;
        }

        // Optionally, you can delete the token after validation
        redisTemplate.delete("resetToken:" + token);
        
        return true;
    }
    

}
