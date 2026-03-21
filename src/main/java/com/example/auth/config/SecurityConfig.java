package com.example.auth.config;

import com.example.auth.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // класс конфигурации Spring
@EnableWebSecurity // включает поддержку Spring Security
@EnableMethodSecurity // включает @PreAuthorize для защиты методов
@RequiredArgsConstructor // создает конструктор для final полей
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter; // наш фильтр для JWT

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // отключаем CSRF (не нужно для REST API с JWT)
                .csrf(csrf -> csrf.disable())

                // делаем сессию stateless (не храним состояние)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // настройка доступа к endpoints
                .authorizeHttpRequests(auth -> auth
                        // публичные endpoints (доступны всем)
                        .requestMatchers("/", "/index.html", "/css/**", "/js/**", "/error").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/test/public").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()

                        // все остальные запросы требуют аутентификации
                        .anyRequest().authenticated())

                // для H2 консоли (чтобы работала)
                .headers(headers -> headers.frameOptions(frame -> frame.disable()))

                // добавляем наш JWT фильтр перед стандартным фильтром
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // шифрование паролей
    }
}