package com.example.auth.service;

import com.example.auth.dto.JwtResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.model.Role;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service  // говорит Spring, что это сервис
@RequiredArgsConstructor  // создает конструктор с final полями
@Transactional  // все методы работают с транзакциями
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;  // работа с БД
    private final PasswordEncoder passwordEncoder;  // шифрование паролей
    private final AuthenticationManager authenticationManager;  // менеджер аутентификации
    private final JwtUtils jwtUtils;  // работа с JWT

    @Override
    public JwtResponse register(RegisterRequest request) {
        // 1. Проверяем, свободен ли username
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already taken!");
        }

        // 2. Проверяем, свободен ли email
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already in use!");
        }

        // 3. Создаем нового пользователя
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        // шифруем пароль перед сохранением!
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(Set.of(Role.ROLE_USER));  // даем роль USER

        // 4. Сохраняем в БД
        User savedUser = userRepository.save(user);

        // 5. Сразу логиним пользователя (создаем токен)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateToken(authentication);

        // 6. Возвращаем ответ с токеном
        return new JwtResponse(jwt, savedUser.getId(),
                savedUser.getUsername(), savedUser.getEmail());
    }

    @Override
    public JwtResponse login(LoginRequest request) {
        // 1. Аутентифицируем пользователя
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsernameOrEmail(),
                        request.getPassword()
                )
        );

        // 2. Сохраняем в контекст безопасности
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 3. Генерируем токен
        String jwt = jwtUtils.generateToken(authentication);

        // 4. Получаем данные пользователя
        User user = (User) authentication.getPrincipal();

        // 5. Возвращаем ответ с токеном
        return new JwtResponse(jwt, user.getId(),
                user.getUsername(), user.getEmail());
    }

    @Override
    public User getCurrentUser() {
        // Получаем текущего аутентифицированного пользователя
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (User) authentication.getPrincipal();
    }
}