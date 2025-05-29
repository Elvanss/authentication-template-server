package com.auth.ms_notification.application.Impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.auth.ms_notification.application.INotificationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationServiceImpl implements INotificationService {

    private final JavaMailSender javaMailSender;
    private final Logger logger = LoggerFactory.getLogger(NotificationServiceImpl.class);

    @Override
    @Async
    /**
     * Sends an OTP email to the user.
     *
     * @param to The recipient's email address.
     * @param otp The OTP code to be sent.
     */
    public void sendOtpEmail(String to, Integer otp) {  
        try {
            logger.info("Sending OTP to {}", to);
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Your OTP Code");
            message.setText("Your OTP code is: " + otp + ". It will expire shortly.");
            javaMailSender.send(message);
            logger.info("OTP email sent successfully to {}", to);
        } catch (MailException e) {
            logger.error("Failed to send OTP email to {}: {}", to, e.getMessage(), e);
        }
    }

    @Override
    @Async
    /**
     * Sends an email notification to the user when their account is locked.
     *
     * @param email The email address of the user whose account is locked.
     */
    public void sendLockedAccountEmail(String email) {
        try {
            logger.info("Sending account locked notification to {}", email);
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Account Locked Notification");
            message.setText("Your account has been locked due to multiple failed login attempts. Please contact support for assistance.");
            javaMailSender.send(message);
            logger.info("Account locked email sent successfully to {}", email);
        } catch (MailException e) {
            logger.error("Failed to send account locked email to {}: {}", email, e.getMessage(), e);
        }
    }
}