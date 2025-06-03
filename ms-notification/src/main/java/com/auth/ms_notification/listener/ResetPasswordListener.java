package com.auth.ms_notification.listener;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.security.core.token.TokenService;
import org.springframework.stereotype.Component;

import com.auth.ms_notification.application.INotificationService;
import com.auth.ms_notification.application.ITokenService;
import com.template.shared.api.user.event.EmailRequestEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class ResetPasswordListener {

    private final INotificationService notificationService;
    private final ITokenService tokenService;

    @KafkaListener(topics = "user.account-password.locked", groupId = "notification-group")
    public void listen(EmailRequestEvent event) {
        try {
            String token = tokenService.generateResetToken(event.getEmail());
            notificationService.sendResetPasswordEmail(event.getEmail(), token);
            log.info("Sent reset password email to {}", event.getEmail());
        } catch (Exception e) {
            log.error("Failed to send reset password email to {}", event.getEmail(), e);
        }
    }
}
