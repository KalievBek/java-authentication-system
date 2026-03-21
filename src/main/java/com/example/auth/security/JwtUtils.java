package com.example.auth.security;

// Импорты для работы с JWT
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component // Spring создаст бин этого класса

public class JwtUtils {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JwtUtils.class);

    // Читаем настройки из application.properties
    @Value("${jwt.secret}")
    private String jwtSecret; // секретный ключ для подписи токенов

    @Value("${jwt.expiration}")
    private int jwtExpirationMs; // срок жизни токена в миллисекундах

    /**
     * Создает ключ для подписи из секретной строки
     */
    private Key key() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    /**
     * Генерирует JWT токен для аутентифицированного пользователя
     */
    public String generateToken(Authentication authentication) {
        // Получаем пользователя из объекта аутентификации
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        // Данные, которые хотим сохранить в токене
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", userPrincipal.getUsername());
        claims.put("authorities", userPrincipal.getAuthorities());

        // Собираем токен
        return Jwts.builder()
                .setClaims(claims) // добавляем данные
                .setSubject(userPrincipal.getUsername()) // главное поле - логин
                .setIssuedAt(new Date()) // время создания
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs)) // время истечения
                .signWith(key(), SignatureAlgorithm.HS256) // подписываем
                .compact(); // собираем в строку
    }

    /**
     * Достает логин пользователя из токена
     */
    public String getUsernameFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Универсальный метод для извлечения данных из токена
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Извлекает все данные из токена
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key()) // ключ для проверки подписи
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Проверяет, валидный ли токен
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(token);
            return true; // токен правильный
        } catch (MalformedJwtException e) {
            log.error("Неверный JWT токен: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT токен просрочен: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT токен не поддерживается: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims строка пустая: {}", e.getMessage());
        }
        return false; // токен неправильный
    }
}
