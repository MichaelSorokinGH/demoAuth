package com.example.authentication.controllers;

import com.example.authentication.jwt.JwtRequest;
import com.example.authentication.jwt.JwtResponse;
import com.example.authentication.jwt.RefreshJwtRequest;
import com.example.authentication.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.security.auth.message.AuthException;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest authRequest) throws AuthException {
        final JwtResponse token = authService.login(authRequest);
        return ResponseEntity.ok(token);
    }

    @PostMapping("token")
    public ResponseEntity<JwtResponse> getNewAccessToken(@RequestBody RefreshJwtRequest request) throws AuthException {
        final JwtResponse token = authService.getAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }

    @PostMapping("refresh")
    public ResponseEntity<JwtResponse> getNewRefreshToken(@RequestBody RefreshJwtRequest request) throws AuthException {
        final JwtResponse token = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }
}
//Эндпойнт /api/auth/login принимает JwtRequest, а возвращает JwtResponse с токенами.
//        Эндпойнт /api/auth/token  принимает RefreshJwtRequest c единственным полем refreshToken
//        и возвращает JwtResponse с новым access токеном.
//        И наконец эндпойнт /api/auth/refresh  принимает RefreshJwtRequest
//        и возвращает JwtResponse с новыми токенами.
