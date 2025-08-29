package com.example.logintestbackend.service.impl;

import com.example.logintestbackend.DTO.request.LoginRequest;
import com.example.logintestbackend.DTO.request.RegisterRequest;
import com.example.logintestbackend.DTO.response.AuthResponse;
import com.example.logintestbackend.entity.User;
import com.example.logintestbackend.enums.Provider;
import com.example.logintestbackend.exception.EmailAlreadyExistsException;
import com.example.logintestbackend.exception.EmailNotFoundException;
import com.example.logintestbackend.repository.UserRepository;
import com.example.logintestbackend.security.JwtTokenUtil;
import com.example.logintestbackend.security.TokenBundle;
import com.example.logintestbackend.service.AuthService;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import lombok.*;

/**
 * Implementation of the {@link AuthService} that handles:
 * <ul>
 *     <li>Local login with email & password</li>
 *     <li>Local registration of new accounts</li>
 *     <li>Google OAuth2 login</li>
 * </ul>
 * 
 * This service is responsible for issuing JWT tokens and
 * ensuring accounts are linked correctly between local and OAuth providers.
 */
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepo;
    private final JwtTokenUtil jwtToken;
    private final PasswordEncoder passwordEncoder;


    /**
     * Authenticate a user with email and password.
     * Validates credentials and issues a JWT token.
     *
     * @param request contains email and password
     * @return AuthResponse with token and user info
     */
    @Override
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        final String email = request.getEmail().trim().toLowerCase();

        // Load user
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new EmailNotFoundException("User with email " + email + " not found"));

        // Disallow local login for Google-only accounts
        if (user.getPasswordHash() == null ||
            !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        // Verify password
        if (user.getPasswordHash() == null ||
            !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        TokenBundle tokens = issueTokens(user);
        return toResponse(user, tokens.getAccessToken());
    }

    /**
     * Register a new local user (email + password).
     * Creates the account, encodes the password, and issues a JWT token.
     *
     * @param request contains email, password, and name
     * @return AuthResponse with token and user info
     */
    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        final String email = request.getEmail().trim().toLowerCase();

        // Ensure email is unique
        if (userRepo.findByEmail(email).isPresent()) {
            throw new EmailAlreadyExistsException("Email already in use: " + email);
        }

        // Encode password with BCrypt
        String bcrypt = passwordEncoder.encode(request.getPassword());

        // Build and save new user
        User user = User.builder()
                .email(email)
                .passwordHash(bcrypt)
                .name(request.getName())
                .provider(Provider.LOCAL)
                .enabled(true)
                .build();

        user = userRepo.save(user);

        // Issue token
        TokenBundle tokens = issueTokens(user);
        return toResponse(user, tokens.getAccessToken());
    }

    /**
     * Handle login/registration with Google OAuth2.
     * If the user already exists (by oauthId or email), update their provider info.
     * Otherwise, create a new Google-linked account.
     *
     * @param principal Google OAuth2 principal (with sub, email, name)
     * @param token     ID token provided by Google
     * @return AuthResponse with token and user info
     */
    @Override
    @Transactional
    public AuthResponse googleLogin(OAuth2User principal, String token) {
        String sub   = principal.getAttribute("sub");   // Google user unique ID
        String email = principal.getAttribute("email");
        String name  = principal.getAttribute("name");

        if (sub == null || email == null) {
            throw new IllegalArgumentException("Google user missing sub/email");
        }

        final String norm = email.trim().toLowerCase();

        // Try to find user by oauthId, fallback to email
        User user = userRepo.findByOauthIdAndProvider(sub, Provider.GOOGLE)
                .orElseGet(() -> userRepo.findByEmail(norm).orElse(null));

        // If no user exists, create a new one
        if (user == null) {
            user = User.createGoogle(norm, name, sub);
        } else {
            // Update existing user with Google details
            user.setProvider(Provider.GOOGLE);
            user.setOauthId(sub);
            if (user.getName() == null) user.setName(name);
            user.setEnabled(true);
        }

        // Persist changes
        user = userRepo.save(user);

        // Return auth response with Google token
        return toResponse(user, token);
    }


    // =========================
    // ==== Helper Methods =====
    // =========================

    /**
     * Generate JWT tokens for a user.
     *
     * @param user the authenticated user
     * @return TokenBundle containing access token (no refresh in this impl)
     */
    private TokenBundle issueTokens(User user) {
        Map<String, Object> claims = Map.of(
                "provider", user.getProvider().name(),
                "uid", user.getId()
        );
        String accessToken = jwtToken.generateToken(user.getEmail(), claims);
        return new TokenBundle(accessToken, null);
    }

    /**
     * Convert a User + token into AuthResponse.
     *
     * @param user        the user
     * @param accessToken issued JWT token
     * @return AuthResponse containing token and user info
     */
    private AuthResponse toResponse(User user, String accessToken) {
        AuthResponse res = new AuthResponse();
        res.setAccessToken(accessToken);
        res.setTokenType("Bearer");
        res.setId(user.getId());
        res.setEmail(user.getEmail());
        res.setName(user.getName());
        return res;
    }
}
