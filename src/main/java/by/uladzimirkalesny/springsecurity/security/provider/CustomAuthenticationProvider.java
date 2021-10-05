package by.uladzimirkalesny.springsecurity.security.provider;

import by.uladzimirkalesny.springsecurity.security.authentication.CustomAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

public record CustomAuthenticationProvider(String key) implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {

        String authenticationName = authentication.getName();
        if (authenticationName.equals(key)) {
            return new CustomAuthentication(null, null, null);
        } else {
            throw new BadCredentialsException("Error");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }

}
