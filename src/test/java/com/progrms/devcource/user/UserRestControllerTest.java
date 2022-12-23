package com.progrms.devcource.user;

import com.progrms.devcource.configures.JwtConfigure;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class UserRestControllerTest {

    private JwtConfigure jwtConfigure;

    private TestRestTemplate testTemplate;

    @Autowired
    public void setJwtConfigure(JwtConfigure jwtConfigure) {
        this.jwtConfigure = jwtConfigure;
    }

    @Autowired
    public void setTestTemplate(TestRestTemplate testTemplate) {
        this.testTemplate = testTemplate;
    }

    @Test
    public void JWT_토큰_테스트() {
        assertThat(tokenToName(getToken("user").toString()), is("user"));
        assertThat(tokenToName(getToken("admin").toString()), is("admin"));
    }

    private String getToken(String username) {
        return testTemplate.exchange(
                "/api/user/" + username + "/token",
                HttpMethod.GET,
                null,
                String.class
        ).getBody();
    }

    private String tokenToName(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtConfigure.getHeader(), token);
        return testTemplate.exchange(
                "/api/user/me",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        ).getBody();
    }

}