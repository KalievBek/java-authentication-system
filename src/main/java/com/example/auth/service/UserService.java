package com.example.auth.service;

import com.example.auth.dto.JwtResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.model.User;

public interface UserService {
    JwtResponse register(RegisterRequest request);
    JwtResponse login(LoginRequest request);
    User getCurrentUser();
}