package com.customjar.security.filters;

import com.customjar.security.services.UserAuthServiceProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Deprecated
public class UsernamePasswordAuthFilter extends OncePerRequestFilter {


    private final UserAuthServiceProvider provider;
    private final String secretKey;

    public UsernamePasswordAuthFilter(UserAuthServiceProvider provider, String secretkey){
        this.provider = provider;
        this.secretKey =  secretkey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().contains("/signUp") &&
                HttpMethod.POST.matches(request.getMethod())){
            try{
                SecurityContextHolder.getContext().setAuthentication(
                        provider.validateCredentials(request.getInputStream(), secretKey)
                );
            }catch (RuntimeException e){
                SecurityContextHolder.clearContext();
                throw e;
            }
        }
        filterChain.doFilter(request, response);
    }
}
