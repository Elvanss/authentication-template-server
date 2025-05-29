package com.auth.ms_notification.listener;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import com.auth.ms_notification.application.INotificationService;
import com.auth.ms_notification.event.OtpRequestEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class AccountLockedListener {

    private final INotificationService notificationService; 

    @KafkaListener(topics = "user.account.locked", groupId = "notification-group")
    public void listen(OtpRequestEvent event) {
        try {
            notificationService.sendLockedAccountEmail(event.getEmail());
            log.info("Sent locked email to {}", event.getEmail());
        } catch (Exception e) {
            log.error("Failed to send locked email to {}", event.getEmail(), e);
        }
    }
    
}
