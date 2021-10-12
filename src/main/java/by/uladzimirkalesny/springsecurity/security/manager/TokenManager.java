package by.uladzimirkalesny.springsecurity.security.manager;

import lombok.RequiredArgsConstructor;

import java.util.Set;

@RequiredArgsConstructor
public class TokenManager {

    private final Set<String> tokens;

    public void addToken(String token) {
        tokens.add(token);
    }

    public boolean containsToken(String token) {
        return tokens.contains(token);
    }

}
