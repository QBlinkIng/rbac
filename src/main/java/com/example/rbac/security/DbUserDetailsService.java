package com.example.rbac.security;

import com.example.rbac.domain.*;
import com.example.rbac.repository.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class DbUserDetailsService implements UserDetailsService {

    private final SysUserRepository userRepo;
    private final SysRoleRepository roleRepo;
    private final SysPermissionRepository permissionRepo;
    private final SysUserRoleRepository userRoleRepo;
    private final SysRolePermissionRepository rolePermissionRepo;

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;

    // TTL 可按需调整
    private static final Duration AUTH_CACHE_TTL = Duration.ofMinutes(20);

    public DbUserDetailsService(SysUserRepository userRepo,
                                SysRoleRepository roleRepo,
                                SysPermissionRepository permissionRepo,
                                SysUserRoleRepository userRoleRepo,
                                SysRolePermissionRepository rolePermissionRepo,
                                StringRedisTemplate redis,
                                ObjectMapper objectMapper) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.permissionRepo = permissionRepo;
        this.userRoleRepo = userRoleRepo;
        this.rolePermissionRepo = rolePermissionRepo;
        this.redis = redis;
        this.objectMapper = objectMapper;
    }

    private String permKey(Long userId) {
        return "auth:perm:" + userId;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser u = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (u.getStatus() != null && u.getStatus() == 0) {
            throw new DisabledException("User disabled");
        }
        if (Boolean.TRUE.equals(u.getLocked())) {
            throw new LockedException("User locked");
        }
        // 1) 先尝试从 Redis 读权限
        List<String> permStrings = readPermsFromCache(u.getId());

        // 2) cache miss 再查 DB 计算权限，并回填 Redis
        if (permStrings == null) {
            permStrings = loadPermsFromDb(u.getId());

            writePermsToCache(u.getId(), permStrings);
        }

        List<SimpleGrantedAuthority> authorities = permStrings.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return User.withUsername(u.getUsername())
                .password(u.getPasswordHash())
                .authorities(authorities)
                .build();
    }
    //redis.delete("auth:perm:" + userId);
    private List<String> readPermsFromCache(Long userId) {
        try {
            String json = redis.opsForValue().get(permKey(userId));
            if (json == null || json.isBlank()) return null;
            return objectMapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            // 缓存读失败就当 miss，走 DB
            return null;
        }
    }

    private void writePermsToCache(Long userId, List<String> perms) {
        try {
            String json = objectMapper.writeValueAsString(perms);
            redis.opsForValue().set(permKey(userId), json, AUTH_CACHE_TTL);
        } catch (Exception ignore) {
        }
    }

    /**
     * 只返回 “role.status=1 且 permission.status=1” 的权限字符串
     */
    private List<String> loadPermsFromDb(Long userId) {
        // user -> roles
        List<SysUserRole> userRoles = userRoleRepo.findAllByUserId(userId);
        if (userRoles.isEmpty()) return List.of();

        // 过滤出启用的 roleId
        Set<Long> enabledRoleIds = new HashSet<>();
        for (SysUserRole ur : userRoles) {
            roleRepo.findById(ur.getRoleId()).ifPresent(role -> {
                if (role.getStatus() != null && role.getStatus() == 1) {
                    enabledRoleIds.add(role.getId());
                }
            });
        }
        if (enabledRoleIds.isEmpty()) return List.of();

        // roles -> role_permissions -> permIds
        Set<Long> permIds = new HashSet<>();
        for (Long roleId : enabledRoleIds) {
            List<SysRolePermission> rps = rolePermissionRepo.findAllByRoleId(roleId);
            for (SysRolePermission rp : rps) {
                permIds.add(rp.getPermId());
            }
        }
        if (permIds.isEmpty()) return List.of();

        // permIds -> perms（过滤启用的 permission）
        List<String> out = new ArrayList<>();
        for (Long pid : permIds) {
            permissionRepo.findById(pid).ifPresent(p -> {
                if (p.getStatus() != null && p.getStatus() == 1) {
                    String httpMethod = p.getHttpMethod() == null ? "" : p.getHttpMethod();
                    String path = p.getPath() == null ? "" : p.getPath();

                    // 建议用 “path:METHOD” 格式，更清晰可控
                    out.add(path + httpMethod);
                }
            });
        }

        // 去重
        return out.stream().distinct().toList();
    }
}
