package com.synappsys.medical.controller;

import static com.synappsys.medical.mapper.DoctorMapper.toDoctor;

import com.synappsys.medical.model.Doctor;
import com.synappsys.medical.repository.DoctorRepository;
import com.synappsys.medical.schema.request.DoctorRequest;
import com.synappsys.medical.schema.response.MessageResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller: DoctorController
 * Handles HTTP requests related to doctor registration.
 * Provides endpoints for registering doctors and checking for existing doctors by document number.
 *
 * @author eyepez
 * Creation date 02/07/2025
 */
@CrossOrigin(origins = "*", maxAge = 3600) // Allow cross-origin requests for all origins
@RestController
@RequestMapping("/api/doctors")
@Slf4j
public class DoctorController {

  private final DoctorRepository doctorRepository;

  public DoctorController(DoctorRepository doctorRepository) {
    this.doctorRepository = doctorRepository;
  }

  @PostMapping("")
  public ResponseEntity<MessageResponse> registerDoctor(@Valid @RequestBody DoctorRequest request) {
    log.info("Registering doctor init");
    return doctorRepository.findByDocumentNumber(request.getDocumentNumber())
        .map(existingDoctor -> {
          log.warn("Doctor with document number {} already exists", request.getDocumentNumber());
          return ResponseEntity.badRequest()
              .body(new MessageResponse("Error: Doctor with this document number already exists!"));
        })
        .orElseGet(() -> {
          Doctor savedDoctor = doctorRepository.save(toDoctor(request));
          log.info("Doctor registered successfully: {}", savedDoctor.getId());
          return ResponseEntity.ok(new MessageResponse("Doctor registered successfully!"));
        });
  }
}
