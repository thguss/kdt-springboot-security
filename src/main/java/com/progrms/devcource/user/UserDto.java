package com.progrms.devcource.user;

import lombok.Getter;

@Getter
public class UserDto {

    private final String token;

    private final String username;

    private final String group;

    public UserDto(String token, String username, String group) {
        this.token = token;
        this.username = username;
        this.group = group;
    }

    @Override
    public String toString() {
        return "UserDto{" +
                "token='" + token + '\'' +
                ", username='" + username + '\'' +
                ", group='" + group + '\'' +
                '}';
    }
}
