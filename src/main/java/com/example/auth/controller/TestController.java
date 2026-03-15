package com.example.auth.controller;

import com.example.auth.model.User;
import com.example.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class TestController {

    private final UserService userService;

    // этот endpoint доступен всем (даже без токена)
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("Это публичный endpoint. Доступен всем!");
    }

    // этот endpoint доступен только авторизованным пользователям с ролью USER или ADMIN
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> userEndpoint() {
        User currentUser = userService.getCurrentUser();
        return ResponseEntity.ok("Привет, " + currentUser.getUsername() +
                "! Ты авторизован как пользователь");
    }

    // этот endpoint доступен только ADMIN
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Привет, Админ! У тебя есть доступ к админке");
    }

    // возвращает профиль текущего пользователя
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getProfile() {
        User currentUser = userService.getCurrentUser();
        return ResponseEntity.ok(currentUser);
    }
}