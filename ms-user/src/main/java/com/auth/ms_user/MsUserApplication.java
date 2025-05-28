package com.auth.ms_user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.openfeign.EnableFeignClients;

import com.auth.ms_user.config.KafkaTopicsConfig;

@SpringBootApplication
@EnableFeignClients(basePackages = "com.auth.ms_user.client")
@EnableConfigurationProperties(KafkaTopicsConfig.class)
public class MsUserApplication {

	public static void main(String[] args) {
		SpringApplication.run(MsUserApplication.class, args);
		
	}

}
