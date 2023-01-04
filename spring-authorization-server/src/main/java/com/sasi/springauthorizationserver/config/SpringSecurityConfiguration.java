package com.sasi.springauthorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SpringSecurityConfiguration {

    /**
     * We're calling authorizeRequests.anyRequest().authenticated() to require authentication for all requests
     * We're also providing a form-based authentication by invoking the formLogin(defaults()) method
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()
                )
                .formLogin(withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService users() {
        List<UserDetails> users = new ArrayList<>();
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("user1")
                .password("password")
                .roles("USER")
                .build();
        users.add(user1);

        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("edit")
                .password("password")
                .roles("USER", "EDIT")
                .build();

        UserDetails user3 = User.withDefaultPasswordEncoder()
                .username("delete")
                .password("password")
                .roles("USER", "DELETE")
                .build();
        users.add(user2);
        users.add(user3);
        return new InMemoryUserDetailsManager(users);
    }
}
