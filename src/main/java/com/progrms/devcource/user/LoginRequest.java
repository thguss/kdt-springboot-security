package com.progrms.devcource.user;

import lombok.Getter;

@Getter
public class LoginRequest {

    private String principal;

    private String credentials;

    protected LoginRequest() {}

    public LoginRequest(String principal, String credentials) {
        this.principal = principal;
        this.credentials = credentials;
    }

    @Override
    public String toString() {
        return "LoginRequest{" +
                "principal='" + principal + '\'' +
                ", credentials='" + credentials + '\'' +
                '}';
    }
}
