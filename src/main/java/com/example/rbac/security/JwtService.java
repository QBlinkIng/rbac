package com.example.rbac.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {
    private final SecretKey key;
    private final long expireSeconds;
    private final StringRedisTemplate redis;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expire-seconds}") long expireSeconds,
            StringRedisTemplate redis
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expireSeconds = expireSeconds;
        this.redis = redis;
    }

    public String generateToken(String username,Long id) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("uid",id)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(expireSeconds)))
                .signWith(key)
                .compact();
    }

    public String parseUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public Long parseUserId(String token) {
        Object uid = parseClaims(token).get("uid");
        if (uid == null) return null;
        if (uid instanceof Number n) return n.longValue();
        return Long.valueOf(uid.toString());
    }


    public Date parseExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // ================== 黑名单（注销） ==================

    private String blKey(String token) {
        return "jwt:blacklist:" + token;
    }

    /** 注销：把 token 加入黑名单，TTL = token 剩余有效期 */
    public void blacklist(String token) {
        Date exp = parseExpiration(token);
        long ttlMillis = exp.getTime() - System.currentTimeMillis();
        if (ttlMillis <= 0) return; // 已过期不用存

        redis.opsForValue().set(blKey(token), "1", Duration.ofMillis(ttlMillis));
    }

    /** 校验：token 是否已被注销 */
    public boolean isBlacklisted(String token) {
        Boolean exists = redis.hasKey(blKey(token));
        return Boolean.TRUE.equals(exists);
    }
}
