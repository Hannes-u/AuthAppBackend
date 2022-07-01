package com.example.authapp.Service;

import com.example.authapp.Entity.Role;
import com.example.authapp.Entity.User;
import com.example.authapp.Exception.AlreadyExistsException;
import com.example.authapp.Repo.RoleRepo;
import com.example.authapp.Repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;

@Service
public class UserService implements UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }

    public User saveUser(User user){
        if (userRepo.findByUsername(user.getUsername()).isPresent()){
            throw new AlreadyExistsException("User with Username "+user.getUsername()+" already exists.");
        }
        for (Role role: user.getRoles()){
            roleRepo.findByName(role.getName()).orElseThrow(() -> new NoSuchElementException("Role "+role.getName()+" does not exist."));
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    public User findByUsername(String username){
        return userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
    }

    public Role findByRoleName(String name){
        return roleRepo.findByName(name).orElseThrow();
    }

    public List<User> getAllUsers(){
        return userRepo.findAll();
    }

    public void addRoleToUser(String role, String username){
        User user = findByUsername(username);
        Role role1 = findByRoleName(role);
        user.getRoles().add(role1);
        userRepo.save(user);
    }

    public Role saveRole(Role role){
        return roleRepo.save(role);
    }

    public List<Role> findAllRoles(){
        return roleRepo.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username);
        return user.getUserDetails();
    }
}
