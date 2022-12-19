package com.progrms.devcource.configures;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomAuthenticationEventHandler {

    @Async
    @EventListener
    public void handleAuthenticationSuccessHandler(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        log.info("Successful authentication result : {}", authentication.getPrincipal());
    }

    @EventListener
    public void handleAuthenticationFailureHandler(AbstractAuthenticationFailureEvent event) {
        Exception e = event.getException();
        Authentication authentication = event.getAuthentication();
        log.info("Unsuccessful authentication result : {}", authentication.getPrincipal(), e);
    }
}
