package com.synappsys.medical.repository;

import com.synappsys.medical.model.EmployeeRole;
import com.synappsys.medical.model.Role;
import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Interface: RoleRepository
 * Repository interface for managing Role entities in the MongoDB database.
 * Provides methods to perform CRUD operations and custom queries for roles.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
public interface RoleRepository extends MongoRepository<Role, String> {

  /**
   * Find a Role by its name.
   *
   * @param name The name of the role represented as an EmployeeRole enum.
   * @return An Optional containing the Role if found, or empty if not found.
   */
  Optional<Role> findByName(EmployeeRole name);
}
