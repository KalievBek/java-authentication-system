package com.example.auth.controller;

import com.example.auth.dto.JwtResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController  // этот класс обрабатывает HTTP запросы
@RequestMapping("/api/auth")  // все URL начинаются с /api/auth
@RequiredArgsConstructor  // создает конструктор
@CrossOrigin(origins = "*", maxAge = 3600)  // разрешает запросы с других доменов
public class AuthController {

    private final UserService userService;  // внедряем сервис

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            // пытаемся зарегистрировать
            JwtResponse response = userService.register(request);
            return ResponseEntity.ok(response);  // 200 OK
        } catch (RuntimeException e) {
            // если ошибка (логин занят и т.д.)
            return ResponseEntity.badRequest().body(e.getMessage());  // 400 Bad Request
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            // пытаемся войти
            JwtResponse response = userService.login(request);
            return ResponseEntity.ok(response);  // 200 OK
        } catch (Exception e) {
            // если пароль неверный или пользователь не найден
            return ResponseEntity.badRequest().body("Invalid username/email or password");
        }
    }
}