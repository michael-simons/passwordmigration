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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
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

/**
 * This is a really bad idea, don't ever use this password encoder at home. It's just here
 * for illustrating purposes.
 */
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

    private static final Logger LOG = LoggerFactory
        .getLogger(SecurityConfiguration.class);


    /**
     * This configures the new delegating password encoder system. More hints inside the
     * method.
     *
     * @return The systemwide password encoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // This is the id of the default encoder that is used for *encoding*
        // new passwords
        final String idForEncode = "pbkdf2";
        // And that is the actual encoder for the above id. I need this on a variable
        // later on.
        final Pbkdf2PasswordEncoder defaultEncoder = new Pbkdf2PasswordEncoder();

        // Create the chain of password encoders
        final Map<String, PasswordEncoder> encoders
            = new HashMap<>();
        // We're gonna use pbkdf2 and some other secure hashes
        // This reads as: "We can decode all password hashes that starts with one of the keys in the map."
        encoders.put(
            idForEncode, defaultEncoder);
        encoders.put(
            "bcrypt", new BCryptPasswordEncoder());
        encoders.put(
            "scrypt", new SCryptPasswordEncoder());

        // The final, delegating password encoder. First parameter configures the default
        // encoder for matching.
        final DelegatingPasswordEncoder rv =
            new DelegatingPasswordEncoder(idForEncode, encoders);
        // !!!!
        // That is the crucial part to support "legacy" passworts without a hash
        // Usually (and hopefully) that would be something like a sha1, maybe md5, but
        // not the one I configured here ;)
        rv.setDefaultPasswordEncoderForMatches(new BSPasswordEncoder());
        return rv;
    }

    /**
     * This is where you connect your user database with the application. For the
     * purpose of this demo, I'm using an in-memory based solution.
     * <br>
     * Notice that I'm not using {@link InMemoryUserDetailsManagerConfigurer} from within
     * {@link #webSecurityConfigurer(AuthenticationEventPublisher, UserDetailsService)}.
     * That configurer would have gave me the ability to set the password encoder.
     * Which would defeat the purpose of this demo, so I use the super secret, incredible
     * hard to guess password hash <pre>fvzbaf</pre>.
     *
     * @return Your custom user details service
     */
    @Bean
    public UserDetailsService userDetailsService() {
        final InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager
            .createUser(withUsername("michael")
                .password("fvzbaf") // This is treated as a password hash
                .roles("user")
                .build()
            );
        return manager;
    }

    /**
     * This bean is needed to publish security events like successfull and failed logins.
     * Spring Boot 2M7 still creates that for you, but that might change in the future.
     *
     * @param publisher
     * @return
     */
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(
        final ApplicationEventPublisher publisher
    ) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    /**
     * This {@link WebSecurityConfigurerAdapter} takes care of all things security.
     * Take note that as of Spring Boot 2 having one of those in the context, all Spring Boots
     * magic goes away. All defaults are courtesy of Spring Security itself.
     *
     * @param authenticationEventPublisher
     * @param userDetailsService
     * @return
     */
    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurer(
        final AuthenticationEventPublisher authenticationEventPublisher,
        final UserDetailsService userDetailsService
    ) {
        return new WebSecurityConfigurerAdapter() {
            @Override
            protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                // @formatter:off
                auth
                        // That is actually insecure!! But if you want to migrate the password,
                        // we have to keep the credentials inside the authentication object.
                        // Luckily for use, the credentials are the clear text password
                        // in case of username and password authenticatio
                        .eraseCredentials(false)
                        // Register the authenticationEventPublisher with security, otherwise no events will be fired
                        .authenticationEventPublisher(authenticationEventPublisher)
                        // Register the rest of our infrastructure.
                        .userDetailsService(userDetailsService)
                        .passwordEncoder(passwordEncoder());
                // @formatter:on
            }
        };
    }


    /**
     * This method represents the "guts" of this demo: It listens on
     * {@link AuthenticationSuccessEvent authentication success events} and checks if the authentication inside them
     * is of a {@link UsernamePasswordAuthenticationToken} with credentials being availabe.
     *
     * @param passwordEncoder That is the new, delegating password encoder.
     * @return
     */
    @Bean
    public ApplicationListener<AuthenticationSuccessEvent> onSuccessListener(
        final PasswordEncoder passwordEncoder)
    {
        return (AuthenticationSuccessEvent event) -> {
            final Authentication authentication = event.getAuthentication();
            if (authentication instanceof UsernamePasswordAuthenticationToken && authentication.getCredentials() != null) {
                // That is the point where we are able to retrieve the users login name
                // and also the clear text password if we didn't let Spring Security erase the credentials
                // We now can use the delegating password encoder to rehash the password to a safe hash
                final CharSequence plainTextPassword = (CharSequence) authentication.getCredentials();
                final String rehashedPassword = passwordEncoder.encode(plainTextPassword);

                LOG.info("Now is the time to store new password hash {} for user {}", rehashedPassword, authentication.getName());
            }
        };
    }
}

/**
 * Just a simple controller to try the stuff above.
 */
@Controller
class DemoController {

    @GetMapping("/")
    public String index() {
        return "index";
    }
}
