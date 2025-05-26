package com.auth.ms_user.utils;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.stereotype.Component;

import com.auth.ms_user.config.KafkaTopicsConfig;

import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;


@Component
@AllArgsConstructor
public class KafkaTopicCreator {

    private final KafkaAdmin kafkaAdmin;
    private final KafkaTopicsConfig kafkaTopicsConfig;

    @PostConstruct
    public void createTopics() {
        kafkaTopicsConfig.getTopics().getProduced().forEach(t -> {
            NewTopic topic = TopicBuilder.name(t.getName())
                .partitions(t.getPartitions())
                .replicas(t.getReplicationFactor())
                .configs(t.getConfig())
                .build();
            kafkaAdmin.createOrModifyTopics(topic);
        });
    }
}

