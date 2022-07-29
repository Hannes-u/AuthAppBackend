package com.example.authapp.security.jwt;

import com.example.authapp.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  private final Key secret = Keys.secretKeyFor(SignatureAlgorithm.HS512);

  @Value("${authApp.jwtExpirationMs}")
  private int jwtExpirationMs;

  public  int getJwtExpirations(){
    return jwtExpirationMs;
  }

  public String generateJwtToken(Authentication authentication,String userFingerprint) throws UnsupportedEncodingException, NoSuchAlgorithmException {

      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
      String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
    return Jwts.builder()
            .claim("userFingerprint",userFingerprintHash)
            .setSubject((userPrincipal.getUsername()))
            .setIssuedAt(new Date())
            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
            .signWith(secret)
            .compact();
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken, String userFingerprint) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
      String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);
      Jwts.parserBuilder().setSigningKey(secret).require("userFingerprint",userFingerprintHash)
              .build().parseClaimsJws(authToken);
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
    } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
     logger.error("Something went wrong while hashing fingerprint!");
    }

    return false;
  }
}
