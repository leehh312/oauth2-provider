package com.idp.common.dto;

import java.time.Instant;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class UserSignInfo {
    private String familyName;
    private String givenName;
    private String username;
    private String password;
    private String phoneNumber;
    private boolean validPhoneNumber;
    private String email;
    private boolean isValidEmail;
    private String birthdate;
    private String gender;
    private String address;
    private Instant updatedAt;
}
