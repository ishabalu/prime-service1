package edu.iu.isaikuma.primeservice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import com.nimbusds.jose.jwk.RSAKey;

@Component
public class Jwks {

    private final KeyGeneratorUtils keyGeneratorUtils;

    @Autowired
    public Jwks(KeyGeneratorUtils keyGeneratorUtils) {
        this.keyGeneratorUtils = keyGeneratorUtils;
    }

    public RSAKey generateRsa() { // Removed the static keyword
        KeyPair keyPair = keyGeneratorUtils.generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}
