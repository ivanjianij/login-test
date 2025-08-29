// src/main/java/com/example/logintestbackend/security/GoogleOAuth2UserService.java
package com.example.logintestbackend.security;

import com.example.logintestbackend.entity.User;
import com.example.logintestbackend.enums.Provider;
import com.example.logintestbackend.repository.UserRepository;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import lombok.*;
import lombok.extern.slf4j.Slf4j;


/**
 * Custom OIDC user service for Google logins.
 *
 * Extends Spring's {@link OidcUserService} to:
 *  - Fetch Google user info (sub, email, name)
 *  - Upsert a local {@link User} entity in the database
 *  - Ensure provider is set to GOOGLE
 *  - Return the standard {@link OidcUser} for downstream success handler
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class GoogleOAuth2UserService extends OidcUserService {

    private final UserRepository users;

    /**
     * Loads and processes the Google OIDC user.
     *
     * Steps:
     *  1. Delegate to default {@link OidcUserService} to get Google claims
     *  2. Extract "sub", "email", and "name"
     *  3. Find existing user in DB by (sub, provider) or fallback to email
     *  4. If not found → create new user
     *  5. Update fields (provider, sub, name, enabled)
     *  6. Save & flush user immediately (ensures availability for later)
     *  7. Return the {@link OidcUser} back to Spring Security
     */
    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest req) throws OAuth2AuthenticationException {
        // Step 1: Delegate to default OidcUserService
        OidcUser user = super.loadUser(req);

        // Step 2: Extract required claims
        String sub   = user.getSubject();
        String email = user.getEmail();
        String name  = user.getFullName() != null ? user.getFullName() : (String) user.getClaims().get("name");

        if (sub == null || email == null) {
            throw new OAuth2AuthenticationException("Missing Google sub/email");
        }
        String normalized = email.trim().toLowerCase();

        // Step 3: Try to find existing user (first by OAuth ID, then fallback by email)
        User u = users.findByOauthIdAndProvider(sub, Provider.GOOGLE)
                      .orElseGet(() -> users.findByEmail(normalized).orElse(null));

        // Step 4: Create new user if not found
        if (u == null) {
            u = User.createGoogle(normalized, name, sub);
        } else {
            // Step 5: Update existing user fields
            u.setProvider(Provider.GOOGLE);
            u.setOauthId(sub);
            if (u.getName() == null) u.setName(name);
            u.setEnabled(true);
        }
        // Step 6: Save user (flush ensures immediate visibility for transaction)
        users.saveAndFlush(u);
        log.info("Upserted Google user {}", normalized);

        // Step 7: Return OidcUser for Spring Security flow
        return user;
    }
}
