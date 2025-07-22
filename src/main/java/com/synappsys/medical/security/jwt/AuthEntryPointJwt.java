package com.synappsys.medical.security.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * Class: AuthEntryPointJwt
 * Custom implementation of AuthenticationEntryPoint to handle unauthorized access.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
@Component // Indicate that this class is a Spring component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

  private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class); // Logger for logging errors

  /**
   * Handle unauthorized access attempts.
   *
   * @param request       The HTTP request.
   * @param response      The HTTP response.
   * @param authException The exception that was thrown during authentication.
   * @throws IOException      If an input or output exception occurs.
   * @throws ServletException If a servlet-related exception occurs.
   */
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationException authException) throws IOException, ServletException {
    // Log the unauthorized access attempt with the exception message
    logger.error("Unauthorized error: {}", authException.getMessage());

    // Send an HTTP response with a 401 Unauthorized status and an error message
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
  }

}
