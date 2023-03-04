package com.example.authentication.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JwtResponse {

    private final String type = "Bearer";

    private String accessToken;

    private String refreshToken;
//    JwtResponse, который будет содержать access и refresh токены. Этот объект мы будем возвращать в ответ.
}
