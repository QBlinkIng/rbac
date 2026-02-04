package com.example.rbac.controller;

import com.example.rbac.audit.Audit;
import com.example.rbac.domain.SysPermission;
import com.example.rbac.domain.SysRolePermission;
import com.example.rbac.domain.SysUserRole;
import com.example.rbac.domain.dot.CreatePermissionRequest;
import com.example.rbac.domain.dot.EditPermissionRequest;
import com.example.rbac.repository.SysPermissionRepository;
import com.example.rbac.repository.SysRolePermissionRepository;
import com.example.rbac.repository.SysUserRoleRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/permissions")
public class PermissionController {

    private final SysPermissionRepository permRepo;
    private final StringRedisTemplate redis;
    private final SysUserRoleRepository userRoleRepo;
    private final SysRolePermissionRepository rolePermissionRepo;
    public PermissionController(SysPermissionRepository permRepo, StringRedisTemplate redis, SysUserRoleRepository userRoleRepo, SysRolePermissionRepository rolePermissionRepo) {
        this.permRepo = permRepo;
        this.redis = redis;
        this.userRoleRepo = userRoleRepo;
        this.rolePermissionRepo = rolePermissionRepo;
    }

    // 只有管理员能创建权限
    @Audit(action = "CREATE", resourceType = "PREMISSION", resourceId = "#result")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @PostMapping("")
    public Long create(@Validated @RequestBody CreatePermissionRequest req) {
        SysPermission p = new SysPermission();
        p.setPermissionCode(req.permissionCode);
        p.setPermissionName(req.permissionName);
        p.setPermissionType(req.permissionType == null ? "API" : req.permissionType);
        p.setPath(req.path);
        p.setRemark(req.remark);
        p.setStatus((byte) 1);
        p.setHttpMethod(req.httpMethod);

        try {
            return permRepo.save(p).getId();
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "permissionCode already exists");
        }
    }

    // 修改权限（建议 PUT）
    @Audit(action = "UPDATE", resourceType = "PREMISSION", resourceId = "#result.id")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @PutMapping("/{code}")
    public SysPermission edit(@Validated @RequestBody EditPermissionRequest req,@PathVariable String code) {
        if (req.permissionCode == null || req.permissionCode.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "permissionCode is required");
        }

        SysPermission p = permRepo.findByPermissionCode(code)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "permission not found"));

        if (req.permissionName != null) p.setPermissionName(req.permissionName);
        if (req.permissionType != null) p.setPermissionType(req.permissionType);
        if (req.httpMethod != null) p.setHttpMethod(req.httpMethod);
        if (req.path != null) p.setPath(req.path);
        if (req.remark != null) p.setRemark(req.remark);
        p.setStatus(req.status);
        try {
            permRepo.save(p);
            List<SysRolePermission> roper = rolePermissionRepo.findAllByPermId(p.getId());
            for(SysRolePermission rp : roper) {
                List<SysUserRole> t = userRoleRepo.findAllByRoleId(rp.getRoleId());
                for(SysUserRole u : t) {
                    redis.delete("auth:perm:" + u.getUserId());
                }
            }
            return p;
        } catch (DataIntegrityViolationException e) {
            // 例如你未来允许改 permCode 时会出现冲突（此版本没允许改 code）
            throw new ResponseStatusException(HttpStatus.CONFLICT, "conflict");
        }
    }

    // 删除权限：用 code 删除更直观
    @Audit(action = "DELETE", resourceType = "PREMISSION", resourceId = "#result.id")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @DeleteMapping("/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public SysPermission delete(@PathVariable("code") String code) {
        SysPermission p = permRepo.findByPermissionCode(code)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "permission not found"));
        List<SysRolePermission> roper = rolePermissionRepo.findAllByPermId(p.getId());
        for(SysRolePermission rp : roper) {
            List<SysUserRole> t = userRoleRepo.findAllByRoleId(rp.getRoleId());
            for(SysUserRole u : t) {
                redis.delete("auth:perm:" + u.getUserId());
            }
        }
        permRepo.delete(p);
        return p;
    }

    // 查询权限：GET 不用 body，用 path 变量
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @GetMapping("/{code}")
    public SysPermission get(@PathVariable("code") String code) {
        return permRepo.findByPermissionCode(code)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "permission not found"));
    }
}
