package com.customjar.security.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.customjar.security.exceptionHandler.customExceptions.InvalidTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class TokenService {


    DecodedJWT verifySignature(String token, String secretKey) {
        try {
//            byte[] decodedKey = Base64.getUrlDecoder().decode(this.key);
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        } catch (TokenExpiredException tokenExpiredException) {
            throw new InvalidTokenException("JWT Token Expired");
        } catch (SignatureVerificationException exception) {
            throw new InvalidTokenException("Invalid token signature potential harmful token");
        }
    }



    public Map generateToken(String secretKey) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, secretKey);
    }

    private Map doGenerateToken(Map<String, Object> claims, String secretKey) {
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        long expTime = System.currentTimeMillis() + 1000*60*60*24*15;
        String jwt =  JWT.create()
                .withClaim("tokenId", getTokenId())
                .withClaim("claim",claims)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000*60*60*24*15))
                .sign(algorithm);
        Map<String, Object> tokenResponse = new HashMap<>();
        tokenResponse.put("token", jwt);
        tokenResponse.put("expTime", expTime);
        return tokenResponse;
    }


    private String getTokenId(){
        final String capsAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        final String smallAlpha= capsAlpha.toLowerCase(Locale.ROOT);
        final String num = "1234567890";
        final  String AlphaNumericString = capsAlpha+smallAlpha+num;
        final int n = 12;
        StringBuilder sb = new StringBuilder(n);
        int firstIndex = (int) ((capsAlpha.length()+smallAlpha.length()) * Math.random());
        sb.append((capsAlpha+smallAlpha).charAt(firstIndex));
        for (int i = 2; i <= n; i++) {
            int index = (int)(AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString
                    .charAt(index));
        }
        return sb.toString();
    }
}
