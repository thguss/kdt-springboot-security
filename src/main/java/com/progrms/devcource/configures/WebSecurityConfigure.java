package com.progrms.devcource.configures;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/assets/**");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                    .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
                    .anyRequest().permitAll()
                .and()
                .formLogin()
                    .defaultSuccessUrl("/")
                .loginPage("/my-login")
                .usernameParameter("my-username")
                .passwordParameter("my-password")
                .permitAll()
                .and()
                /**
                 * 로그아웃 설정
                 */
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/")
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                .and()
                /**
                 * remember-me 설정
                 */
                .rememberMe()
                    .rememberMeParameter("remember-me")
                    .tokenValiditySeconds(300)
                .and()
                /**
                 * HTTP 요청을 HTTPS 요청으로 다이렉트
                 */
                .requiresChannel()
                    .anyRequest()
                    .requiresSecure()
                .and()
                .anonymous()
                    .principal("thisIsAnonymousUser")
                    .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
                .and()
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                .and()
                .sessionManagement()
                .sessionFixation().changeSessionId()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/")
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .and()
        ;
        return http.build();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_ACCEPTED);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user123"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
