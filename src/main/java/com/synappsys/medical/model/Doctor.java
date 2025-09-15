package com.synappsys.medical.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Class: Doctor
 * MongoDB document representing a doctor request with all required fields.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
@Data
@Document(collection = "doctors")
@NoArgsConstructor
@AllArgsConstructor
public class Doctor {

  @Id
  private String id;

  @NotBlank
  private String firstName;

  @NotBlank
  private String lastName;

  @NotBlank
  private String documentType;

  @NotBlank
  private String documentNumber;

  @NotBlank
  private String gender;

  @NotBlank
  @Email
  private String email;

  @NotBlank
  private String mobile;

  @NotNull
  private String birthdate;
}
