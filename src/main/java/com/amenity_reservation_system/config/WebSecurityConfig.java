package com.amenity_reservation_system.config;

import com.amenity_reservation_system.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig implements SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity> {

    private final UserDetailsServiceImpl userDetailsService;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final String[] SECURITY_IGNORED_ENDPOINTS = {
            "/h2-console/**", "/h2/**", "/webjars/**"
    };

    public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(SECURITY_IGNORED_ENDPOINTS);
    }

    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .logout()
                .permitAll()
                .logoutSuccessUrl("/");
    }

    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        // Initialization logic
    }
}