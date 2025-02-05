package com.codewithabdo.aroundU.models;

import jakarta.validation.constraints.*;

public class RegisterDto {


    @NotEmpty
    private String username;

    @NotEmpty
    private String email;

    private String phone;

    private String address;

    private String profileImage;

    @NotEmpty
    @Size(min = 6, message = "Minimum password length is 6 characters")
    private String password;

    // Getters and Setters


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getProfileImage() {
        return profileImage;
    }

    public void setProfileImage(String profileImage) {
        this.profileImage = profileImage;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}