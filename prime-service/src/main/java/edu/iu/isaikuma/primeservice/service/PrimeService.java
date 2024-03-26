package edu.iu.isaikuma.primeservice.service;

import org.springframework.stereotype.Service;

@Service
public class PrimeService implements IprimeService {
    @Override

    public boolean isPrime(long n){
        if (n==2){
            return true;

        }

        for (long i=2L;i<n;i++){
            if(n%i==0){
                return false;
            }

        }
        return true;
    }

}
