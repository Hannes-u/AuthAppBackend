package com.example.authapp.security.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@RequiredArgsConstructor
@Getter
@Setter
public class JwtResponse {

    @JsonProperty("access_token")
    private String accessToken;
    private UserDetails userDetails;

    private List<String> roles;

    private String message;
    private Status status;
    private String exceptionType;
    private String jwt;
    private Jws<Claims> jws;

    public JwtResponse(String access_token, UserDetails user) {
        this.accessToken = access_token;
        this.userDetails = user;
    }

    public enum Status {
        SUCCESS, ERROR
    }

}
