package com.example.logintestbackend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.logintestbackend.entity.User;
import com.example.logintestbackend.enums.Provider;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find a user by their email address (case-insensitive usually enforced at service level).
     *
     * @param email user email
     * @return Optional containing the User if found, empty otherwise
     */
    Optional<User> findByEmail(String email);

    /**
     * Find a user by their OAuth provider ID and provider type.
     * Useful for Google/Facebook login to link external identity to local account.
     *
     * @param oauthId  unique ID returned by the OAuth provider
     * @param provider provider type (e.g., GOOGLE, LOCAL)
     * @return Optional containing the User if found, empty otherwise
     */
    Optional<User> findByOauthIdAndProvider(String oauthId, Provider provider);

    /**
     * Check if a user already exists with the given email.
     * Useful for preventing duplicate registrations.
     *
     * @param email user email
     * @return true if a user with this email exists, false otherwise
     */
    boolean existsByEmail(String email);
}
