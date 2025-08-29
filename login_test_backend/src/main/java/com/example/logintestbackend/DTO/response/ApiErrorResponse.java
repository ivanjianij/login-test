package com.example.logintestbackend.DTO.response;

import java.time.LocalDateTime;

public record ApiErrorResponse(
    LocalDateTime timestamp,
    int status,
    String error,
    String message
) {}
