package com.abdul.SpringbootSecurityDemoAmCode.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    //extends OncePerRequestFilter and implement it to invoke it once per single request
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Get your authorization header
        String authorizationHeader = request.getHeader("Authorization");

        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) { //choose Strings of com.google.common.base
            filterChain.doFilter(request, response); //Filter the request and the response
            return;

        }

        // try and catch and parse your token, get the body and the subject and the authorities using List mapping

        try {
            String token = authorizationHeader.replace("Bearer", ""); // Replace Bearer with empty string to grab the token alone
            String secretKey = "SecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecureSecure";
            Jws<Claims> claimsJws = Jwts.parser()      // you Parse the token
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes())) //pass thesame key like you did in username and password filter class
                    .parseClaimsJws(token);//after compact a signed jwt is called jws  //Then extract it into a variable using cnttl + alt + v

//            GET THE BODY AND USE THE BODY TO GET THE SUBJECT, AUTHORITIES USING CLAIMS AS YOUR TYPE remove the = and extract all
            Claims body = claimsJws.getBody();
            String username = body.getSubject();
            var authorities = (List<Map<String, String>>) body.get("authorities"); //Create a var of authorities and List Map it with String

//            authorities maping using authorities.stream and map each authority with obj of simpleGrantedAuthorities and collect the sets using .collect and then extract it
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            // create Authentication authentication new UsernamePasswordAuthenticationToken() and pass authentication in setAuth;
            // Use SecurityContextHolder to .get the context() and .set the Authentication(authentication)
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities // map this with each key using stream
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e ){
            throw new IllegalStateException("Token can not the trusted");
        }

        filterChain.doFilter(request, response);
    }

}
