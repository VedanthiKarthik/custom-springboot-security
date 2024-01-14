package com.customjar.security.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.customjar.security.dto.AccessTokenInfoDto;
import com.customjar.security.exceptionHandler.customExceptions.InvalidTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class TokenValidator {
    private final String key;

    public AccessTokenInfoDto validateToken(String token) {
        try {
            TokenService tokenService = new TokenService();
            DecodedJWT jwt = decodeJWT(token);
            jwt = tokenService.verifySignature(token, this.key);
            Map<String, Claim> claimMap = jwt.getClaims();
            AccessTokenInfoDto accessTokenInfoDto = new AccessTokenInfoDto();
            accessTokenInfoDto.setClaimsData(claimMap.get("claim").asMap());
            accessTokenInfoDto.setStatus("Success");
            accessTokenInfoDto.setMessage("valid token");
//            accessTokenInfoDto.setUser(claimMap.get("user").asString());
            return accessTokenInfoDto;
        } catch (Exception e) {
            throw new InvalidTokenException(e.getMessage());
        }
    }

/*    private DecodedJWT verifySignature(String token) {
        try {
//            byte[] decodedKey = Base64.getUrlDecoder().decode(this.key);
            Algorithm algorithm = Algorithm.HMAC256(this.key);
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        } catch (TokenExpiredException tokenExpiredException) {
            throw new InvalidTokenException("JWT Token Expired");
        } catch (SignatureVerificationException exception) {
            throw new InvalidTokenException("Invalid token signature potential harmful token");
        }
    }*/

    private DecodedJWT decodeJWT(String token) {
        try {
            if (token.isBlank()) {
                throw new IllegalArgumentException("No JWT Token found in the header");
            }
            return JWT.decode(token);
        } catch (IllegalArgumentException | JWTDecodeException exception) {
            throw new InvalidTokenException(exception.getMessage());
        }
    }
}
