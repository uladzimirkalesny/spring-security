package by.uladzimirkalesny.springsecurity.service.security;

import by.uladzimirkalesny.springsecurity.entity.User;
import by.uladzimirkalesny.springsecurity.repository.UserJpaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor

@Component
public class UserJpaDetailsService implements UserDetailsService {

    private final UserJpaRepository userJpaRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User foundUser = userJpaRepository.findUsersByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User with username [" + username + "] not found!"));
        return new SpringSecurityUser(foundUser);
    }

}
