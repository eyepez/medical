package com.synappsys.medical.controller;

import com.synappsys.medical.model.EmployeeRole;
import com.synappsys.medical.model.Role;
import com.synappsys.medical.model.User;
import com.synappsys.medical.repository.RoleRepository;
import com.synappsys.medical.repository.UserRepository;
import com.synappsys.medical.schema.request.LoginRequest;
import com.synappsys.medical.schema.request.SignupRequest;
import com.synappsys.medical.schema.response.JwtResponse;
import com.synappsys.medical.schema.response.MessageResponse;
import com.synappsys.medical.security.jwt.JwtUtils;
import com.synappsys.medical.security.services.UserDetailsImpl;
import com.synappsys.medical.util.Constants;
import jakarta.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600) // Allow cross-origin requests for all origins
@RestController // Indicate that this class is a REST controller
@RequestMapping("/api/auth") // Base URL for authentication-related endpoints
public class AuthController {

  private final AuthenticationManager authenticationManager; // Handles user authentication
  private final UserRepository userRepository; // Repository for user-related database operations
  private final RoleRepository roleRepository; // Repository for role-related database operations
  private final PasswordEncoder encoder; // Encoder for password hashing
  private final JwtUtils jwtUtils; // Utility for generating JWT tokens

  public AuthController(AuthenticationManager authenticationManager,
                        UserRepository userRepository,
                        RoleRepository roleRepository,
                        PasswordEncoder encoder,
                        JwtUtils jwtUtils) {
    this.authenticationManager = authenticationManager;
    this.userRepository = userRepository;
    this.roleRepository = roleRepository;
    this.encoder = encoder;
    this.jwtUtils = jwtUtils;
  }

  /**
   * Authenticate user and return a JWT token if successful.
   *
   * @param loginRequest The login request containing username and password.
   * @return A ResponseEntity containing the JWT response or an error message.
   */
  @PostMapping("/signin")
  public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    // Authenticate the user with the provided username and password
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
            loginRequest.getPassword()));

    // Set the authentication in the security context
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // Generate JWT token based on the authentication
    String jwt = jwtUtils.generateJwtToken(authentication);

    // Get user details from the authentication object
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    // Extract user roles into a list
    List<String> roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();

    // Return a response containing the JWT and user details
    return ResponseEntity.ok(new JwtResponse(jwt,
        userDetails.getId(),
        userDetails.getUsername(),
        userDetails.getEmail(),
        roles));
  }

  /**
   * Register a new user account.
   *
   * @param signUpRequest The signup request containing user details.
   * @return A ResponseEntity indicating success or error message.
   */
  @PostMapping("/signup")
  public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

    // Check if the username is already taken
    if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    // Check if the email is already in use
    if (Boolean.TRUE.equals(userRepository.existsByEmail(signUpRequest.getEmail()))) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create a new user's account
    User user = new User(signUpRequest.getUsername(),
        signUpRequest.getEmail(),
        encoder.encode(signUpRequest.getPassword())); // Encode the password

    Set<String> strRoles = signUpRequest.getRoles(); // Get the roles from the request
    Set<Role> roles = new HashSet<>(); // Initialize a set to hold the user roles

    // Assign roles based on the request or default to user role
    if (strRoles == null) {
      Role userRole = roleRepository.findByName(EmployeeRole.ROLE_USER)
          .orElseThrow(() -> new RuntimeException(Constants.ERROR_ROLE_NOT_FOUND));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(EmployeeRole.ROLE_ADMIN)
                .orElseThrow(() -> new RuntimeException(Constants.ERROR_ROLE_NOT_FOUND));
            roles.add(adminRole);
            break;
          case "mod":
            Role modRole = roleRepository.findByName(EmployeeRole.ROLE_MODERATOR)
                .orElseThrow(() -> new RuntimeException(Constants.ERROR_ROLE_NOT_FOUND));
            roles.add(modRole);
            break;
          default:
            Role userRole = roleRepository.findByName(EmployeeRole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException(Constants.ERROR_ROLE_NOT_FOUND));
            roles.add(userRole);
        }
      });
    }

    // Assign roles to the user and save it to the database
    user.setRoles(roles);
    userRepository.save(user);

    // Return a success message upon successful registration
    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }
}
