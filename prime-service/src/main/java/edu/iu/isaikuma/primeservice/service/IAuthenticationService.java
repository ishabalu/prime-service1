package edu.iu.isaikuma.primeservice.service;

import edu.iu.isaikuma.primeservice.model.Customer;

import java.io.IOException;

public interface IAuthenticationService {

    boolean register (Customer customer) throws IOException;
    boolean login(String username,String password) throws IOException;

}
