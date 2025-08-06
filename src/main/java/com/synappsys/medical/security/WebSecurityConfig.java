package com.synappsys.medical.security;

import com.synappsys.medical.security.jwt.AuthEntryPointJwt;
import com.synappsys.medical.security.jwt.AuthTokenFilter;
import com.synappsys.medical.security.services.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Class: WebSecurityConfig
 * Configures Spring Security for the application, including authentication, authorization,
 * password encoding, and JWT filter integration.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
@Configuration // Marks the class as a source of bean definitions
@EnableMethodSecurity // Enables method-level security annotations
public class WebSecurityConfig {

  private final UserDetailsServiceImpl userDetailsService; // Injects the user details service for authentication
  private final AuthEntryPointJwt unauthorizedHandler; // Injects the entry point for unauthorized requests

  public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, AuthEntryPointJwt unauthorizedHandler) {
    this.userDetailsService = userDetailsService;
    this.unauthorizedHandler = unauthorizedHandler;
  }

  /**
   * Creates a bean for the authentication JWT token filter.
   *
   * @return AuthTokenFilter instance
   */
  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter(); // Returns a new instance of AuthTokenFilter
  }

  /**
   * Creates a bean for the DAO authentication provider.
   *
   * @return DaoAuthenticationProvider instance
   */
  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); // Create a new authentication provider

    authProvider.setUserDetailsService(userDetailsService); // Set the user details service
    authProvider.setPasswordEncoder(passwordEncoder()); // Set the password encoder

    return authProvider; // Return the configured authentication provider
  }

  /**
   * Creates a bean for the authentication manager.
   *
   * @param authConfig Authentication configuration
   * @return AuthenticationManager instance
   * @throws Exception if there is an error getting the authentication manager
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager(); // Returns the authentication manager from the configuration
  }

  /**
   * Creates a bean for the password encoder.
   *
   * @return PasswordEncoder instance
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // Returns a new instance of BCryptPasswordEncoder
  }

  /**
   * Configures the security filter chain for HTTP requests.
   *
   * @param http HttpSecurity configuration
   * @return SecurityFilterChain instance
   * @throws Exception if there is an error configuring the security filter chain
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // Configure CSRF protection, exception handling, session management, and authorization
    http.csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection
            .exceptionHandling(exception ->
                    exception.authenticationEntryPoint(unauthorizedHandler))
            // Set unauthorized handler
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Set session policy to stateless
            .authorizeHttpRequests(auth -> auth
                    // Configure authorization for HTTP requests
                    .requestMatchers("/api/auth/**").permitAll()
                    // Allow public access to auth endpoints
                    .requestMatchers("/api/test/**").permitAll()
                    // Allow public access to test endpoints
                    .anyRequest().authenticated());
    // Require authentication for any other request

    http.authenticationProvider(authenticationProvider()); // Set the authentication provider

    // Add the JWT token filter before the username/password authentication filter
    http.addFilterBefore(authenticationJwtTokenFilter(),
            UsernamePasswordAuthenticationFilter.class);

    return http.build(); // Build and return the security filter chain
  }
}
