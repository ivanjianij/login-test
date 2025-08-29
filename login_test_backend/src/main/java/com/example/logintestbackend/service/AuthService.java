package com.example.logintestbackend.service;

import com.example.logintestbackend.DTO.request.LoginRequest;
import com.example.logintestbackend.DTO.request.RegisterRequest;
import com.example.logintestbackend.DTO.response.AuthResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface AuthService {

    /**
     * Local email/password login.
     *
     * @param request login request containing email and password
     * @return authentication response with JWT tokens and user info
     */
    AuthResponse login(LoginRequest request);

    /**
     * Register a new local account.
     *
     * @param request registration request with name, email, and password
     * @return authentication response with JWT tokens and user info
     */
    AuthResponse register(RegisterRequest request);

    /**
     * Handle login or registration via Google OAuth2.
     *
     * @param principal OAuth2 principal returned by Google
     * @param token     Google-issued ID token (used directly as access token)
     * @return authentication response with provided token and user info
     */
    AuthResponse googleLogin(OAuth2User principal, String token);
}