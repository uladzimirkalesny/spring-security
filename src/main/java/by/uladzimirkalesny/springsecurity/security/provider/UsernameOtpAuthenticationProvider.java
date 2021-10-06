package by.uladzimirkalesny.springsecurity.security.provider;

import by.uladzimirkalesny.springsecurity.repository.OtpRepository;
import by.uladzimirkalesny.springsecurity.security.authentication.UsernameOtpAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

public record UsernameOtpAuthenticationProvider(OtpRepository otpRepository) implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String otp = String.valueOf(authentication.getCredentials());

        if (otpRepository.findOtpByUsername(username).isPresent()) {
            return new UsernameOtpAuthentication(username, otp, List.of(() -> "read"));
        }
        throw new BadCredentialsException("Error");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernameOtpAuthentication.class.equals(authentication);
    }
}
