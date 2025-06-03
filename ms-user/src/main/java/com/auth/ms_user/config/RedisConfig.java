package com.auth.ms_user.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    // @Bean
    // public RedisTemplate<String, Boolean> redisTemplate(RedisConnectionFactory connectionFactory) {
    //     RedisTemplate<String, Boolean> template = new RedisTemplate<>();
    //     template.setConnectionFactory(connectionFactory);
    //     template.setKeySerializer(new StringRedisSerializer());
    //     template.setValueSerializer(new GenericToStringSerializer<>(Boolean.class));
    //     return template;
    // }

    // @Bean
    // public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
    //     RedisTemplate<String, Object> template = new RedisTemplate<>();
    //     template.setConnectionFactory(connectionFactory);

    //     StringRedisSerializer stringSerializer = new StringRedisSerializer();

    //     // Use String serializer for keys and values
    //     template.setKeySerializer(stringSerializer);
    //     template.setValueSerializer(stringSerializer);
    //     template.setHashKeySerializer(stringSerializer);
    //     template.setHashValueSerializer(stringSerializer);

    //     template.afterPropertiesSet();
    //     return template;
    // }

    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
    
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
    
        // Use String serializer for keys and values
        template.setKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setHashValueSerializer(stringSerializer);
    
        template.afterPropertiesSet();
        return template;
    }

}
