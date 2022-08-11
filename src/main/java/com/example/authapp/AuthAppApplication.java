package com.example.authapp;

import com.example.authapp.controller.service.UserService;
import com.example.authapp.models.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.NoSuchElementException;

@SpringBootApplication
public class AuthAppApplication {

	public static void main(String[] args) {
    SpringApplication.run(AuthAppApplication.class, args);
	}

	//Anlegen von einem Admin User beim erstmaligen Start der Applikation.
	@Bean
	CommandLineRunner runner(UserService userService) {
		return args -> {
			try {
				userService.findByUsername("admin");
			}catch (NoSuchElementException e){
				userService.saveUser(new User("admin","admin@mail.de","Ad@1999@Password"));
			}
		};
	}

}
