package com.example.auth.dto;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @Notblank(message = "Username or email is required")
    private String usernameOrEmail;

    NotBlank(message = "Password is required")
    private String password;
}
