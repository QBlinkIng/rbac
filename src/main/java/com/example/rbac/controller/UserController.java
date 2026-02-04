package com.example.rbac.controller;

import com.example.rbac.audit.Audit;
import com.example.rbac.domain.SysUser;
import com.example.rbac.domain.dot.CreateUserRequest;
import com.example.rbac.domain.dot.CreateUserResponse;
import com.example.rbac.domain.dot.DeleteUserRequest;
import com.example.rbac.domain.dot.EditMeRequest;
import com.example.rbac.repository.SysUserRepository;
import com.example.rbac.security.JwtService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final SysUserRepository userRepo;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redis;
    public UserController(SysUserRepository userRepo, JwtService jwtService, PasswordEncoder passwordEncoder, StringRedisTemplate redis) {
        this.userRepo = userRepo;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.redis = redis;
    }
    /** 更新当前用户信息：PUT /api/users/me */
    @PutMapping("/1")
    @Audit(action = "UPDATE_AUTH", resourceType = "USER", resourceId = "#result.id")
    public SysUser updateMe1(@Validated @RequestBody EditMeRequest req,
                            Authentication authentication) {

        String username = authentication.getName();
        SysUser u = userRepo.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (req.nickname != null) u.setNickname(req.nickname);
        if (req.email != null) u.setEmail(req.email);
        if (req.phone != null) u.setPhone(req.phone);
        return userRepo.save(u);
    }
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @Audit(action = "UPDATE", resourceType = "USER", resourceId = "#result.id")
    @PutMapping()
    public SysUser updateMe(@Validated @RequestBody EditMeRequest req,
                            Authentication authentication) {

        String username = authentication.getName();
        SysUser u = userRepo.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (req.nickname != null) u.setNickname(req.nickname);
        if (req.email != null) u.setEmail(req.email);
        if (req.phone != null) u.setPhone(req.phone);
        u.setLocked(req.locked);
        u.setStatus(req.status);
        redis.delete("auth:perm:" + u.getId());
        return userRepo.save(u);
    }

    /** 注销：POST /api/users/logout （把当前 token 拉黑）*/
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        String token = extractBearerTokenOrBadRequest(authHeader);
        jwtService.blacklist(token);
    }

    /** 删除自己账号：DELETE /api/users/me （删库 + 拉黑当前 token）*/
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @Audit(action = "DELETE", resourceType = "USER", resourceId = "#result.id")
    @DeleteMapping("/{username}")
    @Transactional
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public SysUser deleteMe(Authentication authentication,
                         @RequestHeader(value = "Authorization", required = false) String authHeader,
                         @PathVariable String username) {

        SysUser u = userRepo.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        redis.delete("auth:perm:" + u.getId());
        userRepo.delete(u);
        return u;
    }
    @Audit(action = "CREATE", resourceType = "USER", resourceId = "#result.id")
    @PreAuthorize("hasAuthority('/**ADMIN') or hasAuthority('/api/users/**POST')")
    @PostMapping("/create")
    public CreateUserResponse createuser(@Validated @RequestBody CreateUserRequest req){
        String hash = passwordEncoder.encode(req.password);
        // 3) 组装实体（注意：不要 setId）
        SysUser u = new SysUser();
        u.setUsername(req.username);
        u.setPasswordHash(hash);
        u.setStatus((byte) 1);
        u.setLocked(false);
        u.setNickname(req.nickname);
        u.setEmail(req.email);
        u.setPhone(req.phone);
        // 3) 兜底：防止并发下两个人同时创建同名用户
        try {
            SysUser saved = userRepo.save(u);
            return new CreateUserResponse(saved.getId());
        } catch (DataIntegrityViolationException e) {
            // 通常就是 unique 约束冲突
            throw new ResponseStatusException(HttpStatus.CONFLICT, "username already exists");
        }
    }
    /** 工具：统一提取 Bearer token */
    private String extractBearerTokenOrBadRequest(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing Bearer token");
        }
        return authHeader.substring(7).trim();
    }
}
