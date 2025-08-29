package com.example.logintestbackend.entity;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import com.example.logintestbackend.enums.Provider;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Builder
@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(
    name = "users",
    uniqueConstraints = {
        @UniqueConstraint(name = "ux_users_email", columnNames = "email"),
        @UniqueConstraint(name = "ux_users_oauth_id", columnNames = "oauth_id")
    }
)
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @NotBlank
    @Column(name = "email", nullable = false)
    private String email;

    @JsonIgnore
    @Column(name = "password_hash")
    private String passwordHash;

    @Column(name = "name")
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name="provider", nullable = false)
    private Provider provider;   // LOCAL or GOOGLE

    @Column(name = "oauth_id")
    private String oauthId;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    @CreationTimestamp
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    @UpdateTimestamp
    private Instant updatedAt;


    public static User createGoogle(String email, String name, String sub) {
        return User.builder()
                .email(email)
                .name(name)
                .provider(Provider.GOOGLE)
                .oauthId(sub)
                .enabled(true)
                .build();
    }

    public static User createLocal(String email, String bcryptHash, String name) {
        return User.builder()
                .email(email)
                .passwordHash(bcryptHash)
                .name(name)
                .provider(Provider.LOCAL)
                .enabled(true)
                .build();
    }
}
