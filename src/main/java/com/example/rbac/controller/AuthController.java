package com.example.rbac.controller;

import com.example.rbac.domain.dot.CreateUserRequest;
import com.example.rbac.domain.dot.CreateUserResponse;
import com.example.rbac.domain.dot.*;
import com.example.rbac.security.JwtService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import com.example.rbac.domain.SysUser;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.example.rbac.repository.SysUserRepository;
import java.time.LocalDateTime;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final SysUserRepository userRepo;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          PasswordEncoder passwordEncoder,
                          SysUserRepository userRepo) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.userRepo = userRepo;
    }

    @PostMapping("/login")
    public LoginResponse login(@Validated @RequestBody LoginRequest req) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username, req.password)
        );
        SysUser u = userRepo.findByUsername(auth.getName()).orElseThrow();
        u.setLastLoginAt(LocalDateTime.now());
        userRepo.save(u); // 触发 @PreUpdate，把 updatedAt 也一起更新

        String token = jwtService.generateToken(auth.getName(),u.getId());
        return new LoginResponse(token);
    }
}
