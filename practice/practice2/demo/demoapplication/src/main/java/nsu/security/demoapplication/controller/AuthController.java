package nsu.security.demoapplication.controller;

import nsu.security.demoapplication.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    private static final Map<String, String[]> USERS = Map.of(
            "admin", new String[]{"admin123", "ADMIN"},
            "user", new String[]{"user123", "USER"}
    );

    private final JwtUtil jwtUtil;

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/auth/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        String[] userData = USERS.get(username);

        if (userData == null || !userData[0].equals(password)) {
            return ResponseEntity.status(401).body("Неверный логин или пароль");
        }

        String token = jwtUtil.generateToken(username, userData[1]);
        return ResponseEntity.ok(token);
    }
}