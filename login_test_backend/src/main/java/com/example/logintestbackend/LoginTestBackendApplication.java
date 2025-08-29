package com.example.logintestbackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan 
public class LoginTestBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginTestBackendApplication.class, args);
    }

}
