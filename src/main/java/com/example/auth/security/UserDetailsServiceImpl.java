package com.example.auth.security;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service  // говорит Spring, что это сервисный слой
@RequiredArgsConstructor  // создает конструктор для final полей
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;  // для работы с БД

    /**
     * Этот метод вызывается Spring Security, когда нужно загрузить пользователя
     * @param usernameOrEmail - может быть как username, так и email
     * @return UserDetails - объект пользователя понятный Spring Security
     */
    @Override
    @Transactional(readOnly = true)  // только чтение, без изменений в БД
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {

        // Ищем пользователя в БД по username или email
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() ->
                        new UsernameNotFoundException("Пользователь не найден: " + usernameOrEmail)
                );

        // Возвращаем пользователя (наш User implements UserDetails)
        return user;
    }
}