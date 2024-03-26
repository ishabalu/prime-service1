package edu.iu.isaikuma.primeservice.controller;

import edu.iu.isaikuma.primeservice.service.IprimeService;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
@RequestMapping("/prime")
public class PrimesController {
    IprimeService primeService;
    public PrimesController(IprimeService primeService){
        this.primeService=primeService;
    }

    @GetMapping("/{n}")
    public boolean isPrime(@PathVariable int n){
        return primeService.isPrime(n);
    }
}
