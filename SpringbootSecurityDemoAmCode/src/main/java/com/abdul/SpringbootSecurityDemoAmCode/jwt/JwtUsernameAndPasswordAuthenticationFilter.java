package com.abdul.SpringbootSecurityDemoAmCode.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationManager authenticationManager1) {
        super(authenticationManager);
        this.authenticationManager = authenticationManager1;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String Key = "SecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecure";
        String token = Jwts.builder()
                .setSubject(authResult.getName()) //use authenticationResult to get the subject name, (the UserName)
                .claim("authorities", authResult.getAuthorities()) // Claim as Body to get the authority by using authenticationResult
                .setIssuedAt(new Date()) //Set the object of Date for setting expire time of the token (date.java.util)
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(21))) //Set the expire date using sql date and localDate
                .signWith(Keys.hmacShaKeyFor(Key.getBytes())) //Create the signature token using Keys.hmacShaKeyFor("String of secure token").getByte
                .compact(); // Compact to compile everything

        response.addHeader("Authorization", "Bearer "+token); // get response of the Authorisation and the token by adding it to the header as a bearer token
    }
}
