package edu.iu.isaikuma.primeservice.service;

import edu.iu.isaikuma.primeservice.model.Customer; // Import the Customer model
import edu.iu.isaikuma.primeservice.repository.IAuthenticationRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Import BCryptPasswordEncoder
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired; // Import Autowired for dependency injection
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException; // Import IOException

@Service
public class AuthenticationService implements IAuthenticationService, UserDetailService{
    private final IAuthenticationRepository authenticationRepository;

    @Autowired // Use Autowired for constructor-based dependency injection
    public AuthenticationService(IAuthenticationRepository authenticationRepository) {
        this.authenticationRepository = authenticationRepository;
    }

    @Override
    public boolean register(Customer customer) throws IOException {
        BCryptPasswordEncoder bc = new BCryptPasswordEncoder();
        String passwordEncoded = bc.encode(customer.getPassword());
        customer.setPassword(passwordEncoded);
        return authenticationRepository.save(customer);
    }
    public boolean login(String username, String password) {
        try {
            Customer customer = authenticationRepository.findByUsername(username);
            if (customer != null && passwordEncoder.matches(password, customer.getPassword())) {
                // The password matches, return true to indicate successful login
                return true;
            } else {
                // If customer not found or password does not match, throw an exception
                throw new UsernameNotFoundException("User not found or password does not match");
            }
        } catch (Exception e) {
            // You can log the exception details here
            throw new RuntimeException("Login failed", e);
        }
    }



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            Customer customer = authenticationRepository.findByUsername(username);
            if(customer == null) {
                throw new UsernameNotFoundException("");
            }
            return User
                    .withUsername(username)
                    .password(customer.getPassword())
                    .build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

