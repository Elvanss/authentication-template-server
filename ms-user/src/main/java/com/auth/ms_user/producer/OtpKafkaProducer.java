package com.auth.ms_user.producer;

import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import com.auth.ms_user.event.OtpRequestEvent;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class OtpKafkaProducer {

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(OtpKafkaProducer.class);
    private final KafkaTemplate<String, OtpRequestEvent> kafkaTemplate;

    public OtpKafkaProducer(KafkaTemplate<String, OtpRequestEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void sendMessage(OtpRequestEvent otpRequestEvent, String topic) {
        CompletableFuture<SendResult<String, OtpRequestEvent>> future = kafkaTemplate.send(topic, otpRequestEvent);
        future.whenComplete((result, ex) -> {
            if (ex == null) {
                logger.info("Send message=[{}] with offset=[{}]", 
                otpRequestEvent, 
                result.getRecordMetadata().offset()
                );
            } else {
                logger.error("Failed to send message=[{}] due to: {}", otpRequestEvent, ex.getMessage());
            }
        });
    }
}