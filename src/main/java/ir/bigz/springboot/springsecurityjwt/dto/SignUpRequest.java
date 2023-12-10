package ir.bigz.springboot.springsecurityjwt.dto;

import lombok.Builder;

@Builder
public record SignUpRequest (String firstName, String lastName, String email, String password){
}
