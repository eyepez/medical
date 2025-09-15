package com.synappsys.medical.mapper;

import com.synappsys.medical.model.Doctor;
import com.synappsys.medical.schema.request.DoctorRequest;
import lombok.experimental.UtilityClass;

@UtilityClass
public class DoctorMapper {

  public static Doctor toDoctor(DoctorRequest request) {
    Doctor doctor = new Doctor();
    doctor.setFirstName(request.getFirstName());
    doctor.setLastName(request.getLastName());
    doctor.setDocumentType(request.getDocumentType());
    doctor.setDocumentNumber(request.getDocumentNumber());
    doctor.setGender(request.getGender());
    doctor.setEmail(request.getEmail());
    doctor.setMobile(request.getMobile());
    doctor.setBirthdate(request.getBirthdate());
    return doctor;
  }
}
