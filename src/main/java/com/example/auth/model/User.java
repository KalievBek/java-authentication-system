package com.example.auth.model;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(unique = true, nullable = false)
    private String password;

    @ElementCollection(name = "user_roles",
    joinColumns = @JoinColumn(name = "user_id"))
    Column(name = "role")
    @Enumerated(EnumType.SRTING)
    private Set<Role> roles;

    // Поля для Spring Security - стандартные флаги
    private boolean enabled = true;
    private boolean accountExpored = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;

    // Даты для аудита
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Spring вызовет этот метод ДО сохранения в БД
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    // Spring вызовет этот метод ПРИ обновлении
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Методы из интерфейса UserDetails

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Преобразуем наши роли в формат, понятный Spring Security
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}

