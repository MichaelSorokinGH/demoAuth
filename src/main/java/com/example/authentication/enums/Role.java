package com.example.authentication.enums;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {

    USER("USER"),
    ADMIN("ADMIN"),
    EXECUTOR("EXECUTOR");
    public final String description;

    @Override
    public String getAuthority() {
        return description;
    }
}
