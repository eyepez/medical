package com.synappsys.medical.security.services;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.synappsys.medical.model.User;
import java.io.Serial;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Class: UserDetailsImpl
 * Implements Spring Security's UserDetails interface to represent user details.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
public class UserDetailsImpl implements UserDetails {

  @Serial
  private static final long serialVersionUID = 1L; // Serializable version identifier

  private String id; // Unique identifier for the user
  private String username; // Username of the user
  private String email; // Email address of the user

  @JsonIgnore // Prevent serialization of the password field
  private String password; // Password of the user

  private Collection<? extends GrantedAuthority> authorities; // Collection of user's authorities (roles)

  /**
   * Constructor to initialize UserDetailsImpl.
   *
   * @param id          The unique identifier of the user.
   * @param username    The username of the user.
   * @param email       The email of the user.
   * @param password    The password of the user.
   * @param authorities The collection of user's authorities.
   */
  public UserDetailsImpl(String id, String username, String email, String password,
                         Collection<? extends GrantedAuthority> authorities) {
    this.id = id; // Set user ID
    this.username = username; // Set username
    this.email = email; // Set email
    this.password = password; // Set password
    this.authorities = authorities; // Set authorities
  }

  /**
   * Builds a UserDetailsImpl instance from a User object.
   *
   * @param user The User object.
   * @return A UserDetailsImpl instance.
   */
  public static UserDetailsImpl build(User user) {
    // Map the roles of the user to GrantedAuthority
    List<GrantedAuthority> authorities = user.getRoles().stream()
        .map(role -> new SimpleGrantedAuthority(role.getName().name())) // Convert each role to SimpleGrantedAuthority
        .collect(Collectors.toList()); // Collect into a list

    // Return a new UserDetailsImpl object
    return new UserDetailsImpl(
        user.getId(), // User ID
        user.getUsername(), // Username
        user.getEmail(), // Email
        user.getPassword(), // Password
        authorities); // User authorities
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities; // Return user's authorities
  }

  public String getId() {
    return id; // Return user ID
  }

  public String getEmail() {
    return email; // Return email
  }

  @Override
  public String getPassword() {
    return password; // Return password
  }

  @Override
  public String getUsername() {
    return username; // Return username
  }

  @Override
  public boolean isAccountNonExpired() {
    return true; // Account is not expired
  }

  @Override
  public boolean isAccountNonLocked() {
    return true; // Account is not locked
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true; // Credentials are not expired
  }

  @Override
  public boolean isEnabled() {
    return true; // Account is enabled
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) // Check if the same object
    {
      return true;
    }
    if (o == null || getClass() != o.getClass()) // Check if the object is null or not of the same class
    {
      return false;
    }
    UserDetailsImpl user = (UserDetailsImpl) o; // Cast to UserDetailsImpl
    return Objects.equals(id, user.id); // Check if IDs are equal
  }
}
