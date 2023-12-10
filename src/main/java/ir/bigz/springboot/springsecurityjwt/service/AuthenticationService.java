package ir.bigz.springboot.springsecurityjwt.service;

import ir.bigz.springboot.springsecurityjwt.dto.JwtAuthenticationResponse;
import ir.bigz.springboot.springsecurityjwt.dto.RefreshTokenRequest;
import ir.bigz.springboot.springsecurityjwt.dto.SignInRequest;
import ir.bigz.springboot.springsecurityjwt.dto.SignUpRequest;
import ir.bigz.springboot.springsecurityjwt.entity.User;

public interface AuthenticationService {

    User signUp(SignUpRequest signUpRequest);
    JwtAuthenticationResponse signIn(SignInRequest signInRequest);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
