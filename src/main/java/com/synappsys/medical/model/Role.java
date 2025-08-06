package com.synappsys.medical.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Class: Role
 * Represents a role assigned to an employee in the system.
 * Each role has a unique identifier and a specific name.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
@Document(collection = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role {

  @Id
  private String id;
  private EmployeeRole name;
}