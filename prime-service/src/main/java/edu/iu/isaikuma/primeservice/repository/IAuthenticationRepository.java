package edu.iu.isaikuma.primeservice.repository;

import edu.iu.isaikuma.primeservice.model.Customer;

import java.io.IOException;

public interface IAuthenticationRepository {
    boolean save(Customer customer) throws IOException;
    Customer findByUsername(String username) throws IOException;
}

