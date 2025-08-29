package com.example.logintestbackend.controller;

import com.example.logintestbackend.DTO.request.LoginRequest;
import com.example.logintestbackend.DTO.request.RegisterRequest;
import com.example.logintestbackend.DTO.response.AuthResponse;
import com.example.logintestbackend.service.impl.AuthServiceImpl;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthServiceImpl authService;
    
    /**
     * Login endpoint for authenticating users with email & password.
     * Returns a JWT token and user details if successful.
     */
    @Operation(summary = "Authenticate/Login")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully authenticated"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials"),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Registration endpoint for creating a new user.
     * Returns a JWT token and user details after successful signup.
     */
    @Operation(summary = "Register a new user")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "User successfully registered"),
        @ApiResponse(responseCode = "400", description = "Invalid input data (e.g. weak password, bad email format)"),
        @ApiResponse(responseCode = "409", description = "User already exists with this email"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/users")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(201).body(response);
    }
}
