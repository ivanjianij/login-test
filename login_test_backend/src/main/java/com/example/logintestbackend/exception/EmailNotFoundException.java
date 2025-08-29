package com.example.logintestbackend.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for when an email is not found during authentication.
 * Extends AuthenticationException so that Spring Security can still handle it properly.
 */
public class EmailNotFoundException extends AuthenticationException {
    public EmailNotFoundException(String message) {
        super(message);
    }
}