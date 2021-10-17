package by.uladzimirkalesny.springsecurity.config;

import by.uladzimirkalesny.springsecurity.repository.OtpRepository;
import by.uladzimirkalesny.springsecurity.repository.UserRepository;
import by.uladzimirkalesny.springsecurity.security.filter.TokenAuthenticationFilter;
import by.uladzimirkalesny.springsecurity.security.filter.UsernamePasswordAuthenticationFilter;
import by.uladzimirkalesny.springsecurity.security.manager.TokenManager;
import by.uladzimirkalesny.springsecurity.security.provider.TokenAuthenticationProvider;
import by.uladzimirkalesny.springsecurity.security.provider.UsernameOtpAuthenticationProvider;
import by.uladzimirkalesny.springsecurity.security.provider.UsernamePasswordAuthenticationProvider;
import by.uladzimirkalesny.springsecurity.service.JpaUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.h2.tools.Server;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;
import java.util.HashSet;

@RequiredArgsConstructor

@Configuration
@EnableAsync
public class ApplicationConfiguration extends WebSecurityConfigurerAdapter {

    private final UserRepository userRepository;
    private final OtpRepository otpRepository;

    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @SneakyThrows
    @Bean
    public Filter usernamePasswordAuthenticationFilter() {
        return new UsernamePasswordAuthenticationFilter(authenticationManagerBean(), otpRepository, tokenManager());
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public UserDetailsService jpaUserDetailsService() {
        return new JpaUserDetailsService(userRepository);
    }

    @Bean
    public AuthenticationProvider usernamePasswordAuthenticationProvider() {
        return new UsernamePasswordAuthenticationProvider(jpaUserDetailsService(), passwordEncoder());
    }

    @Bean
    public AuthenticationProvider usernameOtpAuthenticationProvider() {
        return new UsernameOtpAuthenticationProvider(otpRepository);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth
                .authenticationProvider(usernamePasswordAuthenticationProvider())
                .authenticationProvider(usernameOtpAuthenticationProvider())
                .authenticationProvider(tokenAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterAt(usernamePasswordAuthenticationFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(tokenAuthenticationFilter(), BasicAuthenticationFilter.class);
    }

    @Bean
    public TokenManager tokenManager() {
        return new TokenManager(new HashSet<>());
    }

    @Bean
    public Filter tokenAuthenticationFilter() throws Exception {
        return new TokenAuthenticationFilter(authenticationManagerBean());
    }

    @Bean
    public AuthenticationProvider tokenAuthenticationProvider() {
        return new TokenAuthenticationProvider(tokenManager());
    }

    @Bean
    public InitializingBean initializingBean() {
        return () -> SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    /**
     * Start TCP server for H2 database.
     *
     * @return server instance
     */
    @SneakyThrows
    @Bean(initMethod = "start", destroyMethod = "stop")
    public Server inMemoryH2DatabaseServer() {
        return Server.createTcpServer("-tcp", "-tcpAllowOthers", "-tcpPort", "8082");
    }

}
