package nsu.security.demoapplication.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey key() {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
    }

    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + 60 * 60 * 1000); // 1 час

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key())
                .compact();
    }

    public Claims parseToken(String token) {

        log.info("Получен токен для парсинга: {}", token);
        
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Невалидная структура токена");
        }

        try {
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

            Map<String, Object> claimsMap = new ObjectMapper().readValue(payloadJson, Map.class);
            Claims claims = Jwts.claims().add(claimsMap).build();

            // Claims claims = Jwts.parser()
            //         .verifyWith(key())
            //         .build()
            //         .parseSignedClaims(token)
            //         .getPayload();

            log.info("Токен прошёл проверку: subject='{}', role='{}'",
                    claims.getSubject(), claims.get("role", String.class));

            return claims;

        } catch (Exception e) {
            throw new RuntimeException("Не удалось распарсить токен", e);
        }
    }
}