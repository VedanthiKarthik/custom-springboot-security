package com.customjar.security.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletInputStream;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Deprecated
@Component
public class UserAuthServiceProvider {


    @PostConstruct
    protected void init(){
        //secretKey encode or decode
    }

    public String createToken(String user, String secretekey){
        Date now = new Date();
        Date exp = new Date(now.getTime() + 360000);

        Algorithm algorithm = Algorithm.HMAC256(secretekey);
        return JWT.create()
                .withIssuer(user)
                .withIssuedAt(now)
                .withExpiresAt(exp)
                .sign(algorithm);
    }

    public Authentication validateCredentials(ServletInputStream userCredentials, String secretekey){
        return null;
    }

    public Authentication validateToken(String token, String secretkey){
        Algorithm algorithm = Algorithm.HMAC256(secretkey);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decoded =  verifier.verify(token);


        return null;
    }
}
