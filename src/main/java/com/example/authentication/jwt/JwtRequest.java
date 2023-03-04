package com.example.authentication.jwt;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtRequest {

    String login;

    String password;

//    класс JwtRequest, который пользователь будет присылать, чтобы получить JWT токен.
}
