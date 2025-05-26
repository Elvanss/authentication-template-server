package com.auth.gateway.util;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

// @Component
public class JwtUtils {

    @Value("${spring.security.jwt.public-key}")
    private String publicKeyString; // Public key as a Base64-encoded string

    /**
     * Parses the JWT token and retrieves all claims.
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getPublicKey()) // Use the public key for verification
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Converts the Base64-encoded public key string into a PublicKey object.
     */
    private PublicKey getPublicKey() {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    /**
     * Validates the JWT token.
     */
    public boolean validateToken(String token) {
        try {
            getAllClaimsFromToken(token); // If parsing succeeds, the token is valid
            return true;
        } catch (Exception e) {
            return false; // If any exception occurs, the token is invalid
        }
    }

    /**
     * Retrieves the subject (e.g., email or username) from the JWT token.
     */
    public String getSubjectFromToken(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }
}