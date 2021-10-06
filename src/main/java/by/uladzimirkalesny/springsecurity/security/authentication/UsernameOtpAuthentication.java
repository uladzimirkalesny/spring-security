package by.uladzimirkalesny.springsecurity.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UsernameOtpAuthentication extends UsernamePasswordAuthenticationToken {
    public UsernameOtpAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public UsernameOtpAuthentication(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
