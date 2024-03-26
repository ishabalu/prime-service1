package edu.iu.isaikuma.primeservice.controller;

import edu.iu.isaikuma.primeservice.model.Customer;
import edu.iu.isaikuma.primeservice.service.IAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

// The AuthenticationController should be in a separate file or outside the AuthenticationService class
@RestController
class AuthenticationController {

    private final IAuthenticationService authenticationService;
    private  final AuthenticationManager authenticationManager;


    @Autowired // Use Autowired for constructor-based dependency injection
    public AuthenticationController(IAuthenticationService authenticationService,AuthenticationManager authenticationManager) {
        this.authenticationService = authenticationService;
        this.authenticationManager=authenticationManager;
    }

    @PostMapping("/register")
    public boolean register(@RequestBody Customer customer) {
        try {
            return authenticationService.register(customer);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/login")
    public String login(@RequestBody Customer customer) {
        Authentication authentication = authenticationManager
                .authenticate(
                        new UsernamePasswordAuthenticationToken(
                                customer.getUsername(),
                                customer.getPassword()));
        return "success!";
    }

}
