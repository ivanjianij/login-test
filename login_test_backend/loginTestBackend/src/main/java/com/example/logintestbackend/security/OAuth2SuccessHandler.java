// src/main/java/com/example/logintestbackend/security/OAuth2SuccessHandler.java
package com.example.logintestbackend.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Custom handler that runs when an OAuth2 login succeeds (e.g., Google Sign-In).
 * Instead of redirecting to a default page, we generate a JWT token and return it
 * directly in the HTTP response so the frontend can store/use it.
 */
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenUtil jwtTokenUtil;

    /**
     * Called by Spring Security when OAuth2 login is successful.
     * @param request  the HTTP request
     * @param response the HTTP response where we’ll write our token
     * @param authentication the Authentication object containing the OAuth2 user
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();

        String email = principal.getAttribute("email");
        String name  = principal.getAttribute("name");

        String token = jwtTokenUtil.generateToken(
            email,
            Map.of("name", name, "provider", "GOOGLE")
        );

        try {
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(
                "{ \"message\": \"Login successful\", " +
                "\"token\": \"" + token + "\", " +
                "\"email\": \"" + email + "\", " +
                "\"name\": \"" + name + "\" }"
            );
            response.getWriter().flush();
        } catch (Exception e) {
            throw new RuntimeException("Failed to write login response", e);
        }
    }
}
