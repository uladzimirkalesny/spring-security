package by.uladzimirkalesny.springsecurity.security.provider;

import by.uladzimirkalesny.springsecurity.security.authentication.TokenAuthentication;
import by.uladzimirkalesny.springsecurity.security.manager.TokenManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public record TokenAuthenticationProvider(TokenManager tokenManager) implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String token = authentication.getName();

        if (!tokenManager.containsToken(token)) {
            throw new BadCredentialsException("Error");
        }

        return new TokenAuthentication(token, null, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TokenAuthentication.class.equals(authentication);
    }

}
