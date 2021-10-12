package by.uladzimirkalesny.springsecurity.security.filter;

import by.uladzimirkalesny.springsecurity.entity.Otp;
import by.uladzimirkalesny.springsecurity.repository.OtpRepository;
import by.uladzimirkalesny.springsecurity.security.authentication.UsernameOtpAuthentication;
import by.uladzimirkalesny.springsecurity.security.authentication.UsernamePasswordAuthentication;
import by.uladzimirkalesny.springsecurity.security.manager.TokenManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Random;
import java.util.UUID;

@RequiredArgsConstructor
public class UsernamePasswordAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    private final OtpRepository otpRepository;

    private final TokenManager tokenManager;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String USERNAME_HEADER = "username";
    private static final String PASSWORD_HEADER = "password";
    private static final String OTP_HEADER = "otp";
    private static final String LOGIN_PAGE_PATH = "/login";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) {

        final String usernameHeaderValue = request.getHeader(USERNAME_HEADER);
        final String passwordHeaderValue = request.getHeader(PASSWORD_HEADER);
        final String otpHeaderValue = request.getHeader(OTP_HEADER);

        if (otpHeaderValue == null) {
            Authentication usernamePasswordAuthentication = new UsernamePasswordAuthentication(usernameHeaderValue, passwordHeaderValue);
            authenticationManager.authenticate(usernamePasswordAuthentication);

            Otp otp = new Otp();
            otp.setUsername(usernameHeaderValue);
            otp.setOtp(String.valueOf(new Random().nextInt(999999) + 1000));
            otpRepository.save(otp);
        } else {
            Authentication usernameOtpAuthentication = new UsernameOtpAuthentication(usernameHeaderValue, otpHeaderValue);
            authenticationManager.authenticate(usernameOtpAuthentication);
            var token = String.valueOf(UUID.randomUUID());
            tokenManager.addToken(token);
            response.setHeader(AUTHORIZATION_HEADER, token);
        }

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals(LOGIN_PAGE_PATH);
    }
}
