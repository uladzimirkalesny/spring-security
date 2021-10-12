package by.uladzimirkalesny.springsecurity.security.filter;

import by.uladzimirkalesny.springsecurity.security.authentication.TokenAuthentication;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String LOGIN_PAGE_PATH = "/login";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        var token = request.getHeader(AUTHORIZATION_HEADER);

        Authentication tokenAuthentication = new TokenAuthentication(token, null);
        Authentication fullyAuthenticatedAuthentication = authenticationManager.authenticate(tokenAuthentication);

        SecurityContextHolder.getContext().setAuthentication(fullyAuthenticatedAuthentication);
        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().equals(LOGIN_PAGE_PATH);
    }
}
