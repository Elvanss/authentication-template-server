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
}