package by.uladzimirkalesny.springsecurity.config;

import by.uladzimirkalesny.springsecurity.security.CustomAuthenticationProvider;
import lombok.SneakyThrows;
import org.h2.tools.Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class ApplicationConfiguration extends WebSecurityConfigurerAdapter {

    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    public void setCustomAuthenticationProvider(CustomAuthenticationProvider customAuthenticationProvider) {
        this.customAuthenticationProvider = customAuthenticationProvider;
    }

//    private final CustomAuthenticationProvider customAuthenticationProvider;

//    public ApplicationConfiguration(@Lazy CustomAuthenticationProvider customAuthenticationProvider) {
//        this.customAuthenticationProvider = customAuthenticationProvider;
//    }

    @Bean
    public UserDetailsService userDetailsService() {
        var inMemoryUserDetailsManager = new InMemoryUserDetailsManager();

        inMemoryUserDetailsManager.createUser(User.withUsername("Uladzimir").password("1").authorities("read").build());

        return inMemoryUserDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
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

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(customAuthenticationProvider);
    }

}
