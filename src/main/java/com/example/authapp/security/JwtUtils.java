package com.example.authapp.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    private static final String ROLES_CLAIM = "roles";

    @Value("${authApp.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${authApp.jwtRefreshExpirationMs}")
    private int jwtRefreshExpirationMs;

    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public String generateAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> parseJwtToken(String authToken) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
    }
    public boolean validateJwtToken(String authToken) {
        try {
            parseJwtToken(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String unescapeToken(String token) {
        // if there is a quotation mark at the beginning of the token
        if (token.startsWith("\"")) {
            token = token.substring(1);
        }
        // if there is a quotation mark at the end of the token
        if (token.endsWith("\"")) {
            token = token.substring(0, token.length() - 1);
        }
        return token;
    }

}
