package ir.bigz.springboot.springsecurityjwt.service.impl;

import ir.bigz.springboot.springsecurityjwt.dao.UserRepository;
import ir.bigz.springboot.springsecurityjwt.dto.JwtAuthenticationResponse;
import ir.bigz.springboot.springsecurityjwt.dto.RefreshTokenRequest;
import ir.bigz.springboot.springsecurityjwt.dto.SignInRequest;
import ir.bigz.springboot.springsecurityjwt.dto.SignUpRequest;
import ir.bigz.springboot.springsecurityjwt.entity.Role;
import ir.bigz.springboot.springsecurityjwt.entity.User;
import ir.bigz.springboot.springsecurityjwt.security.JWTService;
import ir.bigz.springboot.springsecurityjwt.service.AuthenticationService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    public AuthenticationServiceImpl(UserRepository userRepository,
                                     PasswordEncoder passwordEncoder,
                                     AuthenticationManager authenticationManager,
                                     JWTService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public User signUp(SignUpRequest signUpRequest) {
        User user = new User();

        user.setEmail(signUpRequest.email());
        user.setFirstName(signUpRequest.firstName());
        user.setLastName(signUpRequest.lastName());
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(signUpRequest.password()));

        return userRepository.save(user);
    }

    public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.email(), signInRequest.password()));

        var user = userRepository.findByEmail(signInRequest.email()).orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        return JwtAuthenticationResponse.builder().token(jwt).refreshToken(refreshToken).build();
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        var userEmail = jwtService.extractUserName(refreshTokenRequest.token());
        var user = userRepository.findByEmail(userEmail).orElseThrow();
        if(jwtService.isTokenValid(refreshTokenRequest.token(), user)) {
            var jwt = jwtService.generateToken(user);

            return JwtAuthenticationResponse.builder().token(jwt).refreshToken(refreshTokenRequest.token()).build();
        }
        return null;
    }
}
