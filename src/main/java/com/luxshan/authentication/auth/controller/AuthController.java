package com.luxshan.authentication.auth.controller;

import com.luxshan.authentication.auth.entity.RefreshToken;
import com.luxshan.authentication.auth.entity.User;
import com.luxshan.authentication.auth.entity.UserRole;
import com.luxshan.authentication.auth.service.AuthService;
import com.luxshan.authentication.auth.service.JwtService;
import com.luxshan.authentication.auth.service.RefreshTokenService;
import com.luxshan.authentication.auth.utils.AuthResponse;
import com.luxshan.authentication.auth.utils.LoginRequest;
import com.luxshan.authentication.auth.utils.RefreshTokenRequest;
import com.luxshan.authentication.auth.utils.RegisterRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthService authService, JwtService jwtService, RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register/{role}")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest, @PathVariable UserRole role){
        return ResponseEntity.ok(authService.register(registerRequest, role));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest){
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenRequest.getRefreshToken());
        User user = refreshToken.getUser();

        String accessToken = jwtService.generateToken(user);

        return ResponseEntity.ok(AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getRefreshToken())
                .build());
    }
}
