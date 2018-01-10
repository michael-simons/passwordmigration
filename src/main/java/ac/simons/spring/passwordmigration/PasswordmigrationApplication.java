/*
 * Copyright 2018 michael-simons.eu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ac.simons.spring.passwordmigration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;

import static java.util.stream.Collectors.joining;
import static org.springframework.security.core.userdetails.User.withUsername;

/**
 * @author Michael J. Simons
 */
@SpringBootApplication
public class PasswordmigrationApplication {

    public static void main(String[] args) {
        SpringApplication.run(PasswordmigrationApplication.class, args);
    }

}

class BSPasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        return rawPassword.chars()
                .map(Character::toUpperCase)
                .mapToObj(c -> Character.toString((char) (Character.isLetter(c) ? ('A' + (c - 26) % 26) : c)))
                .collect(joining());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equalsIgnoreCase(encodedPassword);
    }

}

@Configuration
class SecurityConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        final String idForEncode = "pbkdf2";

        final Pbkdf2PasswordEncoder defaultEncoder = new Pbkdf2PasswordEncoder();

        final Map<String, PasswordEncoder> encoders
            = new HashMap<>();
        encoders.put(
            idForEncode, defaultEncoder);
        encoders.put(
            "bcrypt", new BCryptPasswordEncoder());
        encoders.put(
            "scrypt", new SCryptPasswordEncoder());

        final DelegatingPasswordEncoder rv = new DelegatingPasswordEncoder(idForEncode, encoders);
        rv.setDefaultPasswordEncoderForMatches(new BSPasswordEncoder());
        return rv;
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        final InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager
            .createUser(withUsername("michael")
                .password("fvzbaf")
                .roles("user")
                .build()
            );
        return manager;
    }

    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurer(
        final AuthenticationEventPublisher authenticationEventPublisher,
        final UserDetailsService userDetailsService
    ) {
        return new WebSecurityConfigurerAdapter() {
            @Override
            protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                auth
                        .eraseCredentials(false)
                        .authenticationEventPublisher(authenticationEventPublisher)
                        .userDetailsService(userDetailsService)
                        .passwordEncoder(passwordEncoder());
            }
        };
    }

    @Bean
    public ApplicationListener<AuthenticationSuccessEvent> onSuccessListener(
        final PasswordEncoder passwordEncoder)
    {
        return (AuthenticationSuccessEvent event) -> {
            final Authentication authentication = event.getAuthentication();
            if (authentication instanceof UsernamePasswordAuthenticationToken && authentication.getCredentials() != null) {
                System.out.println(authentication.getCredentials() + " -> " + passwordEncoder.encode((CharSequence) authentication.getCredentials()));
            }
        };
    }
}

@Controller
class DemoController {

    @GetMapping("/")
    public String index() {
        return "index";
    }
}
