package by.uladzimirkalesny.springsecurity.security.model;

import by.uladzimirkalesny.springsecurity.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public record SecurityUser(User user) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "read");
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        // No-op
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // No-op
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // No-op
        return true;
    }

    @Override
    public boolean isEnabled() {
        // No-op
        return true;
    }
}
