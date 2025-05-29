package com.auth.ms_notification.listener;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import com.auth.ms_notification.application.INotificationService;
import com.auth.ms_notification.application.IOtpService;
import com.auth.ms_notification.event.OtpRequestEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class OtpListener {

    private final IOtpService otpService;
    private final INotificationService notificationService;

    @KafkaListener(topics = "user.otp.requested", groupId = "notification-group")
    public void listen(OtpRequestEvent event) {
        try {
            Integer otp = otpService.generateOtp(event.getEmail());
            notificationService.sendOtpEmail(event.getEmail(), otp);
            log.info("Sent OTP to {}", event.getEmail());
        } catch (Exception e) {
            log.error("Failed to send OTP to {}", event.getEmail(), e);
        }
    }

}