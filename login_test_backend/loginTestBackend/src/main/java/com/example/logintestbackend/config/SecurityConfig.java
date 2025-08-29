package com.example.logintestbackend.config;

import com.example.logintestbackend.security.GoogleOAuth2UserService;
import com.example.logintestbackend.security.JwtAuthenticationFilter;
import com.example.logintestbackend.security.OAuth2SuccessHandler;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.*;


/**
 * Main Spring Security configuration.
 * Configures JWT filter, OAuth2 login with Google, CORS, and endpoint access rules.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final GoogleOAuth2UserService googleOAuth2UserService;


    /**
     * Password encoder bean. 
     * Uses BCrypt to hash passwords for local (non-Google) accounts.
     */
    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    /**
     * Defines the security filter chain:
     * - Disable CSRF (stateless API)
     * - Enable CORS
     * - Stateless session management
     * - Configure endpoint authorization
     * - Set up Google OAuth2 login with custom OIDC user service + success handler
     * - Insert JWT filter before UsernamePasswordAuthenticationFilter
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())

             // No HTTP session — every request must carry JWT or OAuth2 token
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
             // Authorization rules for API endpoints
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/api/auth", "/api/auth/**",
                                 "/oauth2/**", "/login/oauth2/**")
                .permitAll()

                // Everythin else requires authentication
                .anyRequest().authenticated()
            )

            // Configure OAuth2 login (Google)
            .oauth2Login(o -> o
                .userInfoEndpoint(u -> u
                    .oidcUserService(googleOAuth2UserService) // IMPORTANT for openid scope
                )
                .successHandler(oAuth2SuccessHandler)
            )

            // Register our JWT filter before Spring Security’s built-in username/password filter
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

            http.httpBasic(h -> h.disable());
            http.formLogin(f -> f.disable());
        return http.build();
    }

    /**
     * Global CORS configuration.
     * Allows all origins, methods, and headers (adjust in production).
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(java.util.List.of("*"));
        c.setAllowedMethods(java.util.List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        c.setAllowedHeaders(java.util.List.of("*"));
        c.setAllowCredentials(true);
        c.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", c);
        return src;
    }
}
