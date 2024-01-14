package com.customjar.security.filters;

import com.customjar.security.services.TokenValidator;
import com.customjar.security.dto.AccessTokenInfoDto;
import com.customjar.security.exceptionHandler.customExceptions.InvalidTokenException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomJWTTokenFilterValidator extends OncePerRequestFilter {

    private final TokenValidator tokenValidator;
//    private final AuthenticationManager authenticationManager;

    private final List<String> excludedUrls;
//    public CustomJWTTokenFilterValidator(TokenValidator tokenValidator,
//                                         AuthenticationManager authenticationManager){
//        this.tokenValidator = tokenValidator;
//    }
    private final AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (!excludedUrls.contains(request.getServletPath())) {
            try {
                String authHeader = request.getHeader("Authorization");
                System.out.println("AuthHeader: "+authHeader);
                if(authHeader == null){
                    throw new Exception("No Authentication Header found");
                }
                String token = getTokenFormHeader(request.getHeader(HttpHeaders.AUTHORIZATION));
                if(token == null || token.isEmpty()){
                    throw new InvalidTokenException("No Token found");
                }
                AccessTokenInfoDto accessTokenInfo = tokenValidator.validateToken(token);
                filterChain.doFilter(request, response);
//                authenticationFailureHandler.onAuthenticationFailure(request, response, new AuthenticationServiceException("Auth failed"));
/*                if (Objects.isNull(authHeader)) {
                    throw new CustomTokenException("JWT token not found");
                }*/
//                String token = getTokenFormHeader(request.getHeader(HttpHeaders.AUTHORIZATION));
//                SecurityContextHolder.setContext(tokenValidator.validateToken(authHeader));
            }
            catch (Exception e){
                authenticationFailureHandler.onAuthenticationFailure(request, response, new InvalidTokenException(e.getMessage()));
            }
/*            catch (AuthenticationException authenticationException) {
                throw authenticationException;
            } catch (TokenExpiredException tokenExpiredException) {
                throw tokenExpiredException;
            }catch (NullPointerException e){
                throw new InvalidTokenException("No Token found");
            }*/
        }
        else {
            filterChain.doFilter(request, response);
        }

    }

    @Override
    protected void doFilterNestedErrorDispatch(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("Error Dispatch");
        filterChain.doFilter(request, response);
    }

/*    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        getFailureHandler().onAuthenticationFailure(request, response, failed);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String authHeader = request.getHeader("Authorization");
        String token = getTokenFormHeader(authHeader);
        tokenValidator.validateToken(token);
        return null;
    }*/


    private String getTokenFormHeader(String authHeader) {
        return authHeader.split("Bearer ")[1];
    }

}
