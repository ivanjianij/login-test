package com.example.logintestbackend.DTO.response;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor 
@NoArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String tokenType;
    private Long id;
    private String email;
    private String name;
}