package com.auth.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

import com.auth.gateway.filter.JwtAuthenticationFilter;


// @Configuration
public class GatewayConfig {

    private final JwtAuthenticationFilter filter;

    public GatewayConfig(JwtAuthenticationFilter filter) {
        this.filter = filter;
    }

    // Define the routes for the API Gateway
    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                // Route for the user-service
                .route("user-service", r -> r.path("/v1/user/**") // Match requests with path starting with /v1/user/
                        .filters(f -> f.filter(filter)) // Apply the JwtAuthenticationFilter to secure the route
                        .uri("lb://user-service")) // Forward the request to the user-service using load balancing

                // Route for the job-service
                .route("job-service", r -> r.path("/v1/job-service/**") // Match requests with path starting with /v1/job-service/
                        .filters(f -> f.filter(filter)) // Apply the JwtAuthenticationFilter to secure the route
                        .uri("lb://job-service")) // Forward the request to the job-service using load balancing

                // Route for the notification-service
                .route("notification-service", r -> r.path("/v1/notification/**") // Match requests with path starting with /v1/notification/
                        .filters(f -> f.filter(filter)) // Apply the JwtAuthenticationFilter to secure the route
                        .uri("lb://notification-service")) // Forward the request to the notification-service using load balancing

                // Route for the auth-service
                .route("auth-service", r -> r.path("/v1/auth/**") // Match requests with path starting with /v1/auth/
                        .uri("lb://auth-service")) // Forward the request to the auth-service without applying the filter

                // Route for the file-storage service
                .route("file-storage", r -> r.path("/v1/file-storage/**") // Match requests with path starting with /v1/file-storage/
                        .filters(f -> f.filter(filter)) // Apply the JwtAuthenticationFilter to secure the route
                        .uri("lb://file-storage")) // Forward the request to the file-storage service using load balancing
            .build(); // Build the RouteLocator object
    }
}