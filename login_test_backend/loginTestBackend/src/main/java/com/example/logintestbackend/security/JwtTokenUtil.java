package com.example.logintestbackend.security;

import com.example.logintestbackend.config.JwtPropertiesConfig;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import lombok.*;

/**
 * Utility class for generating, parsing, and validating JSON Web Tokens (JWT).
 * 
 * Responsibilities:
 * - Issue signed JWT tokens for authenticated users.
 * - Extract claims such as subject (email) from tokens.
 * - Validate tokens (signature, expiration, issuer).
 * - Provide integration with Spring Security's {@link UserDetails}.
 *
 * Configuration values (issuer, secret, token TTL) are injected from {@link JwtPropertiesConfig}.
 */
@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    private final JwtPropertiesConfig jwtPropertiesConfig;

    /**
     * Generate a signed JWT with the given subject (usually the user email) and custom claims.
     *
     * @param subject the JWT subject (e.g., email/username)
     * @param claims  additional claims to embed in the payload
     * @return signed JWT as a string
     */
    public String generateToken(String subject, Map<String, Object> claims) {
        long nowMs = System.currentTimeMillis();
        Date now = new Date(nowMs);
        Date exp = new Date(nowMs + jwtPropertiesConfig.getAccessTokenTtlMins() * 60_000);

        return Jwts.builder()
                .setIssuer(jwtPropertiesConfig.getIssuer())
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(signingKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extract the email from a JWT (alias for {@link #extractSubject}).
     */
    public String extractEmail(String token) {
        return extractSubject(token);
    }

    /**
     * Validate a token against Spring Security's {@link UserDetails}.
     * Checks signature, expiry, issuer, and that subject matches the username.
     *
     * @param token       JWT token
     * @param userDetails authenticated user details
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        if (!validateToken(token)) return false;
        String subject = extractSubject(token);
        return subject != null && subject.equalsIgnoreCase(userDetails.getUsername());
    }

    // ---- Core Helpers ----

    /**
     * Validate a token: checks signature, expiration, and issuer only.
     *
     * @param token JWT token
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Jws<Claims> jws = parseClaims(token);
            Claims c = jws.getBody();
            return c.getExpiration() != null
                    && c.getExpiration().after(new Date())
                    && jwtPropertiesConfig.getIssuer().equals(c.getIssuer());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

   /**
     * Extract subject (usually the email/username) from token.
     */
    public String extractSubject(String token) {
        return parseClaims(token).getBody().getSubject();
    }

    // ---- Internal Methods ----

    /**
     * Parse token and return claims (throws if invalid).
     */
    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey())
                .setAllowedClockSkewSeconds(60) // tolerate small skew
                .build()
                .parseClaimsJws(token);
    }

    /**
     * Build the signing key from the configured secret.
     * Supports both Base64-encoded and raw string secrets.
     * Must be at least 32 bytes for HS256.
     */
    private Key signingKey() {
        // Support Base64 or raw string secrets; ensure ≥ 32 bytes for HS256
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(jwtPropertiesConfig.getSecret());
            if (keyBytes.length < 32) throw new IllegalArgumentException("decoded key too short");
        } catch (Exception ignore) {
            keyBytes = jwtPropertiesConfig.getSecret().getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must be at least 32 bytes for HS256");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }
}