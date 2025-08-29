package com.example.logintestbackend.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.example.logintestbackend.entity.User;
import com.example.logintestbackend.enums.Provider;
import com.example.logintestbackend.exception.EmailNotFoundException;
import com.example.logintestbackend.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserPrincipalService implements UserDetailsService {

    private final UserRepository users;

    /**
     * Loads a user by their email address.
     * This is used by Spring Security during authentication (JWT filter, login, etc.)
     *
     * @param email the email (username) provided by the client
     * @return a Spring Security UserDetails object
     * @throws EmailNotFoundException if the user does not exist or is not allowed to log in
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws EmailNotFoundException {
        // Normalize email
        User u = users.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new EmailNotFoundException("Email not found: " + email));

        // Block local login for Google accounts without password
        if (u.getProvider() == Provider.GOOGLE && (u.getPasswordHash() == null || u.getPasswordHash().isBlank())) {
            throw new EmailNotFoundException("Use Google Sign-In for this account.");
        }

        // Ensure password exists
        String bcrypt = u.getPasswordHash();
        if (bcrypt == null || bcrypt.isBlank()) {
            throw new EmailNotFoundException("Password not set for email: " + email);
        }

        // Return Spring Security compatible user
        return org.springframework.security.core.userdetails.User
                .withUsername(u.getEmail())
                .password(bcrypt)
                .disabled(!u.isEnabled())
                .accountLocked(false)
                .credentialsExpired(false)
                .build();
    }
}
