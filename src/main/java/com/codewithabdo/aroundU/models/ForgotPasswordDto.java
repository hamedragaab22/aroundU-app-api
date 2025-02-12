package com.codewithabdo.aroundU.models;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;



public class ForgotPasswordDto {
    @NotBlank
    @Email
    private String email;

    public ForgotPasswordDto(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
