package com.progrms.devcource.configures;

import com.progrms.devcource.configures.custom.CustomWebSecurityExpressionHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.task.DelegatingSecurityContextTaskExecutor;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    @Bean
    @Qualifier("myAsyncTaskExecutor")
    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setThreadNamePrefix("my-executor-");
        return executor;
    }

    @Bean
    public DelegatingSecurityContextTaskExecutor taskExecutor(
            @Qualifier("myAsyncTaskExecutor") AsyncTaskExecutor delegate
    ) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }

    public WebSecurityConfigure() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    /*
    public SecurityExpressionHandler<FilterInvocation> expressionHandler() {
        return new CustomWebSecurityExpressionHandler(
                new AuthenticationTrustResolverImpl(),
                "ROLE_"
        );
    }
    */

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/me", "/asyncHello", "/someMethod").hasAnyRole("USER", "ADMIN")
            .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
            .anyRequest().permitAll()
            .accessDecisionManager(accessDecisionManager())
            .and()
            .formLogin()
            .defaultSuccessUrl("/")
            .permitAll()
            .and()
            /**
             * Basic Authentication 설정
             */
            .httpBasic()
            .and()
            /**
             * remember me 설정
             */
            .rememberMe()
            .rememberMeParameter("remember-me")
            .tokenValiditySeconds(300)
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
             * HTTP 요청을 HTTPS 요청으로 리다이렉트
             */
            .requiresChannel()
            .anyRequest().requiresSecure()
            .and()
            /**
             * 예외처리 핸들러
             */
            .exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler())
    ;
        return http.build();
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(new WebExpressionVoter());
        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
        return new UnanimousBased(voters);
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

    /*
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user123"))
                .roles("USER")
                .build();

        UserDetails admin01 = User.builder()
                .username("admin01")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        UserDetails admin02 = User.builder()
                .username("admin02")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin01, admin02);
    }
    */

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        return jdbcDao;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
