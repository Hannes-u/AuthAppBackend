package com.example.authapp;

import com.example.authapp.Entity.Role;
import com.example.authapp.Entity.User;
import com.example.authapp.Service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;


@SpringBootApplication
public class AuthAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthAppApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner runner(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null,"Role_User"));
            userService.saveRole(new Role(null,"Role_Admin"));
            userService.saveUser(new User(null,"admin","1234",new ArrayList<>()));
            userService.addRoleToUser("Role_Admin","admin");
        };
    }

}
