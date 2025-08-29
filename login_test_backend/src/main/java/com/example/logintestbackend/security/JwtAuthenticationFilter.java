package com.example.logintestbackend.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.logintestbackend.service.UserPrincipalService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * JWT Authentication Filter.
 *
 * <p>This filter runs once per request (extends {@link OncePerRequestFilter})
 * and is responsible for:
 * <ul>
 *   <li>Extracting the JWT from the "Authorization" header</li>
 *   <li>Validating the JWT via {@link JwtTokenUtil}</li>
 *   <li>Loading the user details from DB ({@link UserPrincipalService})</li>
 *   <li>Building an {@link UsernamePasswordAuthenticationToken} if valid</li>
 *   <li>Setting authentication in the {@link SecurityContextHolder}</li>
 * </ul>
 *
 * If no valid token is found, the request just continues anonymously.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    
    private final JwtTokenUtil jwtToken;
    private final UserPrincipalService userPrincipalService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // 1. Get the Authorization header (expected: "Bearer <token>")
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // If no header or not Bearer, skip and let the chain continue
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extract the token (remove "Bearer " prefix)
        final String jwt = authHeader.substring(7);

        try {
            // 3. Extract email (subject) from token
            final String email = jwtToken.extractEmail(jwt);

            // 4. Authenticate only if email is present and not already authenticated
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Load user from DB
                UserDetails userDetails = userPrincipalService.loadUserByUsername(email);

                // 5. Validate the token against user details
                if (jwtToken.validateToken(jwt, userDetails)) {
                    // Create authentication object
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    // Attach request details (IP, session, etc.)
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // 6. Set authentication in SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception ex) {
            // Log and allow request to continue unauthenticated
            log.warn("JWT authentication failed: {}", ex.getMessage());
        }

        // 7. Continue filter chain
        filterChain.doFilter(request, response);
    }
}