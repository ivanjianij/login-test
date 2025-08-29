package com.example.logintestbackend.security;

import com.example.logintestbackend.service.UserPrincipalService;

import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

/**
 * Custom AuthenticationProvider for **local email/password login**.
 * 
 * Responsibilities:
 *  - Load a user by email (delegates to {@link UserPrincipalService})
 *  - Compare raw password against encoded password in DB (via {@link PasswordEncoder})
 *  - Perform built-in account checks (locked, disabled, expired, etc.)
 *
 * This provider is registered in Spring Security and is called automatically
 * whenever a login request comes in with username/password.
 */
@Component
@Getter
@Setter
public class CustomerAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider{

    private UserPrincipalService userPrincipalService;
    private PasswordEncoder passwordEncoder;

    public CustomerAuthenticationProvider(UserPrincipalService userPrincipalService, PasswordEncoder passwordEncoder) {
        this.userPrincipalService = userPrincipalService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Loads the user by "username" (we treat it as an email here).
     * If user not found → throws {@link BadCredentialsException} to avoid leaking info.
     */
    @Override
    protected UserDetails retrieveUser(String username,
                                       UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        try {
            return userPrincipalService.loadUserByUsername(username); // username == email
        } catch (UsernameNotFoundException ex) {
            // Bubble up as BadCredentials so callers don't learn which field was wrong
            throw new BadCredentialsException("Invalid email or password");
        }
    }


    /**
     * Verifies the provided password and runs account status checks.
     * 
     * Steps:
     *  1. Ensure credentials (password) are provided
     *  2. Compare raw password with encoded DB password
     *  3. Run standard Spring account checks (locked, disabled, expired, etc.)
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {

        Object credentials = authentication.getCredentials();
        if (credentials == null) {
            throw new BadCredentialsException("No credentials provided");
        }

        String presentedPassword = credentials.toString();

        // Verify password
        if (userDetails.getPassword() == null ||
            !passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        // Standard account checks (these also run in AbstractUserDetailsAuthenticationProvider, but explicit is fine)
        if (!userDetails.isAccountNonLocked())   throw new LockedException("Account locked");
        if (!userDetails.isEnabled())            throw new DisabledException("Account disabled");
        if (!userDetails.isAccountNonExpired())  throw new AccountExpiredException("Account expired");
        if (!userDetails.isCredentialsNonExpired()) throw new CredentialsExpiredException("Credentials expired");
    }
}
