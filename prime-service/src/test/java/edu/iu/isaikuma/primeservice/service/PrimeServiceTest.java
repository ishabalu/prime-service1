package edu.iu.isaikuma.primeservice.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PrimeServiceTest {

    PrimeService primeService=new PrimeService();
    @Test
    void _45isNotPrime() {
        int n=45;
        boolean expected =false;
        boolean actual=primeService.isPrime(n);
        assertEquals(expected,actual);
    }

    @Test
    void _285191isPrime() {
        int n=285191;
        boolean expected =true;
        boolean actual=primeService.isPrime(n);
        assertEquals(expected,actual);
    }

    @Test
    void _539828945930573isNotPrime() {
        long n=539828945930573L;
        boolean expected =false;
        boolean actual=primeService.isPrime(n);
        assertEquals(expected,actual);
    }
}