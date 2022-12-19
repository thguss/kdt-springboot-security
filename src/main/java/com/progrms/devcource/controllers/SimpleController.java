package com.progrms.devcource.controllers;

import com.progrms.devcource.services.SimpleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.concurrent.Callable;

@Slf4j
@Controller
public class SimpleController {

    private final SimpleService simpleService;

    public SimpleController(SimpleService simpleService) {
        this.simpleService = simpleService;
    }

    @GetMapping(path = "/asyncHello")
    @ResponseBody
    public Callable<String> asyncHello() {
        log.info("[Before callable] asyncHello started.");
        Callable<String> callable = () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User principal = authentication != null ? (User) authentication.getPrincipal() : null;
            String name = principal != null ? principal.getUsername() : null;
            log.info("[Inside callable] Hello {}", name);
            return "Hello " + name;
        };
        log.info("[After callable] asyncHello completed.");
        return callable;
    }

    @GetMapping(path = "/someMethod")
    @ResponseBody
    public String someMethod() {
        log.info("someMethod started.");
        simpleService.asyncMethod();
        log.info("someMethod completed.");
        return "OK";
    }
}
