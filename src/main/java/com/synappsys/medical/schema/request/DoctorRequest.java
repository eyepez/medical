package com.synappsys.medical.schema.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.io.Serial;
import java.io.Serializable;
import lombok.Data;

@Data
public class DoctorRequest implements Serializable {

  @Serial
  private static final long serialVersionUID = 789456123L;

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
