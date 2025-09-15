package com.synappsys.medical.repository;

import com.synappsys.medical.model.Doctor;
import jakarta.validation.constraints.NotBlank;
import java.util.Optional;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Interface: DoctorRepository
 * Repository interface for managing Doctor entities in the MongoDB database.
 * Provides methods to perform CRUD operations and custom queries for users.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
public interface DoctorRepository extends MongoRepository<Doctor, String> {
  Optional<Doctor> findByDocumentNumber(@NotBlank String documentNumber);
}
