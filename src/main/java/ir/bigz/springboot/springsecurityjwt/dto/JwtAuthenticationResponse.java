package ir.bigz.springboot.springsecurityjwt.dto;

import lombok.Builder;

@Builder
public record JwtAuthenticationResponse(String token, String refreshToken) {
}
