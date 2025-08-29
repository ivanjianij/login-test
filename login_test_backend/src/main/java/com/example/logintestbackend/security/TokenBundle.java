package com.example.logintestbackend.security;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenBundle {
    private final String accessToken;
    private final String refreshToken; // optional; null if you don’t use refresh yet
}
