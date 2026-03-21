package com.example.auth.security;

// Импорты для работы с HTTP и Servlet
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Lombok - для удобства
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

// Spring Security - для аутентификации
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

// Spring
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // Spring создаст бин этого класса
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    // OncePerRequestFilter - фильтр, который выполняется 1 раз для каждого запроса

    // Зависимости, которые Spring внедрит через конструктор
    private final JwtUtils jwtUtils; // наш класс для работы с JWT
    private final UserDetailsService userDetailsService; // сервис для загрузки пользователя из БД

    public JwtAuthenticationFilter(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 1. Пробуем достать JWT токен из запроса
            String jwt = parseJwt(request);

            // 2. Если токен есть и он валидный
            if (jwt != null && jwtUtils.validateToken(jwt)) {

                // 3. Извлекаем username из токена
                String username = jwtUtils.getUsernameFromToken(jwt);

                // 4. Загружаем пользователя из БД по username
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 5. Создаем объект аутентификации
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());

                // 6. Добавляем детали запроса (IP, сессию и т.д.)
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                // 7. Сохраняем аутентификацию в SecurityContext
                // Теперь Spring Security знает, что пользователь авторизован
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("Установлена аутентификация для пользователя: {}", username);
            }
        } catch (Exception e) {
            log.error("Не удалось установить аутентификацию: {}", e.getMessage());
        }

        // 8. Продолжаем цепочку фильтров
        filterChain.doFilter(request, response);
    }

    /**
     * Достает JWT токен из заголовка Authorization
     * Ожидается заголовок: "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        // Проверяем, есть ли заголовок и начинается ли он с "Bearer "
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            // Возвращаем токен без "Bearer "
            return headerAuth.substring(7);
        }

        return null; // токена нет
    }
}