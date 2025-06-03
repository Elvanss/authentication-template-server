package com.auth.ms_user.service;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.auth.ms_user.config.KafkaTopicsConfig;
import com.auth.ms_user.domain.User;
import com.auth.ms_user.producer.OtpKafkaProducer;
import com.template.shared.api.user.event.EmailRequestEvent;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class NotificationService {


    private final KafkaTopicsConfig kafkaTopicsConfig;
    private final OtpKafkaProducer otpKafkaProducer;
    private final Logger logger = LoggerFactory.getLogger(AuthService.class);


    @Async
    public void sendAccountLockedEventAsync(User user) {
        try {
            EmailRequestEvent accountLockedEvent = buildEmailRequestEvent(user);
            otpKafkaProducer.sendMessage(accountLockedEvent, kafkaTopicsConfig.getProducedTopic("user.account.locked").getName());
            logger.info("Account locked event sent to Kafka for user: {}", user.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send account locked event to Kafka for user: {}", user.getEmail(), e);
        }
    }

    @Async 
    public void sendResetPasswordEmailAsync(User user) {
        try {
            EmailRequestEvent resetPasswordEvent = buildEmailRequestEvent(user);
            otpKafkaProducer.sendMessage(resetPasswordEvent, kafkaTopicsConfig.getProducedTopic("user.reset-password.success").getName());
            logger.info("Reset password email sent to: {}", user.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send reset password email to: {}", user.getEmail(), e);
        }
    }

    @Async
    public void sendOtpRequestEventAsync(User user) {
        try {
            EmailRequestEvent otpRequestEvent = buildEmailRequestEvent(user);
            otpKafkaProducer.sendMessage(otpRequestEvent, kafkaTopicsConfig.getProducedTopic("user.otp.requested").getName());
            logger.info("OTP request event sent to Kafka for user: {}", user.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send OTP request event to Kafka for user: {}", user.getEmail(), e);
        }
    }

    /**
     * Build an OtpRequestEvent for the given user.
     * 
     * @param user the user entity
     * @return the OTP request event
     */
    public EmailRequestEvent buildEmailRequestEvent(User user) {
        return new EmailRequestEvent(
            user.getUserId(),
            user.getEmail()
        );
    }

}
