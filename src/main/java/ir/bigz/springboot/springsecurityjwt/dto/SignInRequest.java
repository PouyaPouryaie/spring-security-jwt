package ir.bigz.springboot.springsecurityjwt.dto;

import lombok.Builder;

@Builder
public record SignInRequest(String email, String password) {
}
