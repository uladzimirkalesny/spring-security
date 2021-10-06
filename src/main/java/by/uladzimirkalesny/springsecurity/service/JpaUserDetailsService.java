package by.uladzimirkalesny.springsecurity.service;

import by.uladzimirkalesny.springsecurity.repository.UserRepository;
import by.uladzimirkalesny.springsecurity.security.model.SecurityUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public record JpaUserDetailsService(UserRepository userRepository) implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new SecurityUser(userRepository.findUsersByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Error")));
    }
}
