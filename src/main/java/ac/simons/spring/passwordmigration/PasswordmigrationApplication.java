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

import static java.util.stream.Collectors.joining;
import static org.springframework.security.core.userdetails.User.withUsername;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

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
        // That is the crucial part to support "legacy" passwords without a hash
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
     * a {@link AuthenticationManagerBuilder#inMemoryAuthentication}.
     * That configurer would have gave me the ability to set the password encoder.
     * Which would defeat the purpose of this demo, so I use the super secret, incredible
     * hard to guess password hash <pre>fvzbaf</pre>.
     *
     * @return Your custom user details service
     */
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        final InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager
            .createUser(withUsername("michael")
                .password("fvzbaf") // This is treated as a password hash
                .roles("user")
                .build()
            );
        return manager;
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
