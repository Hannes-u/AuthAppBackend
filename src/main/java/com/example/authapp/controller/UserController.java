package com.example.authapp.controller;

import com.example.authapp.controller.service.UserService;
import com.example.authapp.exception.PasswordInvalidException;
import com.example.authapp.models.User;
import com.example.authapp.models.helper.ChangePasswordRequest;
import com.example.authapp.models.helper.ChangePasswordSuccessfulResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class UserController {
  @Autowired
  UserService userService;


  @GetMapping("/all")
  public List<User> allUsers() {
    return userService.getAllUsers();
  }

  @GetMapping("/getMyInformation")
  public User getInformationOfUser() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

    String username;
    if (principal instanceof UserDetails) {
      username = ((UserDetails) principal).getUsername();
    } else {
      username = principal.toString();
    }

    return userService.findByUsername(username);
  }

  @PutMapping("/changePassword")
  public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest){
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

    String username;
    if (principal instanceof UserDetails) {
      username = ((UserDetails) principal).getUsername();
    } else {
      username = principal.toString();
    }

    try {
      userService.changePassword(username,changePasswordRequest.getPassword());
      return ResponseEntity.ok(new ChangePasswordSuccessfulResponse("Password changed successful!"));
    }catch (PasswordInvalidException passwordInvalidException){
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(passwordInvalidException.getMessage());
    }

  }
}
