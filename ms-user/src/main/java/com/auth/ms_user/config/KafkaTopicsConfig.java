package com.auth.ms_user.config;

import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "kafka")
public class KafkaTopicsConfig {

    private Topics topics;

    @Data
    public static class Topics {
        private List<KafkaTopic> produced;
    }

    @Data
    public static class KafkaTopic {
        private String name;
        private int partitions;
        private int replicationFactor;
        private Map<String, String> config;
    }

    public KafkaTopic getProducedTopic(String topicName) {
        return topics.getProduced().stream()
                .filter(topic -> topic.getName().equals(topicName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Topic not found: " + topicName));
    }
}