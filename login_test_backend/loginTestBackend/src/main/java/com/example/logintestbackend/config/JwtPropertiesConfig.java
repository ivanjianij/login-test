package com.example.logintestbackend.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app.jwt")
public class JwtPropertiesConfig {
    /** Secret key used for HS256 signing (≥ 32 bytes of entropy) */
    @NotBlank
    private String secret;

    /** Access token TTL in minutes */
    @Min(1)
    private long accessTokenTtlMins = 60;

    /** Issuer claim */
    @NotBlank
    private String issuer = "logintestbackend";
}