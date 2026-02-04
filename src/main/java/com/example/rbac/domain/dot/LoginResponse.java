package com.example.rbac.domain.dot;

public class LoginResponse {
    public String accessToken;

    public LoginResponse(String accessToken) {
        this.accessToken = accessToken;
    }
}
