package by.uladzimirkalesny.springsecurity.security.csrf;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomCsrfTokenRepository implements CsrfTokenRepository {

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "123456789");
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {

    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        return null;
    }

}
