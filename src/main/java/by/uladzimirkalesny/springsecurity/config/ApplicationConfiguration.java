package by.uladzimirkalesny.springsecurity.config;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.h2.tools.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;

@RequiredArgsConstructor

@Configuration
public class ApplicationConfiguration extends WebSecurityConfigurerAdapter {

    /**
     * From application.properties / or you should to define bean in the ApplicationConfiguration class.
     */
    private final DataSource dataSource;

    @Bean
    public JdbcUserDetailsManager userDetailsService() {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic();
        http
                .csrf().disable();
        http
                .authorizeRequests()
                .mvcMatchers("/addUser").permitAll()
                .anyRequest().authenticated();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
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
