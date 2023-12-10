package ir.bigz.springboot.springsecurityjwt.dto;

import lombok.Builder;

@Builder
public record RefreshTokenRequest(String token) {
}
