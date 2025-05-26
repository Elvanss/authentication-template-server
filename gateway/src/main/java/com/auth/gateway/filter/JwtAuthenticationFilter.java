package com.auth.gateway.filter;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;

import com.auth.gateway.util.JwtUtils;

import reactor.core.publisher.Mono;

// @Component
public class JwtAuthenticationFilter implements GatewayFilter {
    private final JwtUtils jwtUtils;

    // Constructor to inject the JwtUtil dependency
    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Extract the HTTP request from the exchange
        ServerHttpRequest request = exchange.getRequest();

        // Define a list of API endpoints that do not require authentication
        final List<String> apiEndpoints = List.of("/v1/auth/login", "/v1/auth/register", "/eureka");

        // Predicate to check if the current request is for a secured API endpoint
        Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream()
                .noneMatch(uri -> r.getURI().getPath().contains(uri));

        // If the request is for a secured API endpoint
        if (isApiSecured.test(request)) {
            // Check if the Authorization header is missing
            if (authMissing(request)) return onError(exchange);

            // Extract the token from the Authorization header
            String token = request.getHeaders().getOrEmpty("Authorization").get(0);

            // Remove the "Bearer " prefix from the token if it exists
            if (token != null && token.startsWith("Bearer ")) token = token.substring(7);

            try {
                // Validate the token using JwtUtil
                jwtUtils.validateToken(token);
            } catch (Exception e) {
                // If token validation fails, return an error response
                return onError(exchange);
            }
        }
        // If the request is valid, pass it to the next filter in the chain
        return chain.filter(exchange);
    }

    // Method to handle unauthorized requests
    private Mono<Void> onError(ServerWebExchange exchange) {
        // Get the HTTP response from the exchange
        ServerHttpResponse response = exchange.getResponse();
        // Set the response status to 401 Unauthorized
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        // Complete the response without further processing
        return response.setComplete();
    }

    // Method to check if the Authorization header is missing in the request
    private boolean authMissing(ServerHttpRequest request) {
        // Return true if the Authorization header is not present
        return !request.getHeaders().containsKey("Authorization");
    }
}