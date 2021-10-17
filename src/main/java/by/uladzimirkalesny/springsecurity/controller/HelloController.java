package by.uladzimirkalesny.springsecurity.controller;

import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {

        Runnable runnable = () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            System.out.println(authentication.getName());
        };

        ExecutorService executorService = Executors.newSingleThreadExecutor();
        DelegatingSecurityContextExecutorService delegatingSecurityContextExecutorService =
                new DelegatingSecurityContextExecutorService(executorService);

        delegatingSecurityContextExecutorService.submit(runnable);
        delegatingSecurityContextExecutorService.shutdown();

        return "Hello";
    }

}
