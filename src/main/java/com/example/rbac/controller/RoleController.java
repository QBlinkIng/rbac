package com.example.rbac.controller;

import com.example.rbac.audit.Audit;
import com.example.rbac.domain.SysRole;
import com.example.rbac.domain.SysUserRole;
import com.example.rbac.domain.dot.CreateRoleRequest;
import com.example.rbac.domain.dot.EditRoleRequest;
import com.example.rbac.repository.SysRoleRepository;
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
@RequestMapping("/api/roles")
public class RoleController {

    private final SysRoleRepository roleRepo;
    private final StringRedisTemplate redis;
    private final SysUserRoleRepository userRoleRepo;
    public RoleController(SysRoleRepository roleRepo, StringRedisTemplate redis, SysUserRoleRepository userRoleRepo) {
        this.roleRepo = roleRepo;
        this.redis = redis;
        this.userRoleRepo = userRoleRepo;
    }

    // 创建角色：POST /api/roles
    @Audit(action = "CREATE", resourceType = "ROLE", resourceId = "#result")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @PostMapping
    public Long create(@Validated @RequestBody CreateRoleRequest req) {
        SysRole r = new SysRole();
        r.setStatus((byte) 1);
        r.setRoleCode(req.roleCode);
        r.setRoleName(req.roleName);
        r.setRemark(req.remark);

        try {
            Long re = roleRepo.save(r).getId();
            return re;
        } catch (DataIntegrityViolationException e) {
            // 通常是 UNIQUE 冲突（role_code 或 role_name）
            throw new ResponseStatusException(HttpStatus.CONFLICT, "roleCode/roleName already exists");
        }
    }
    @Audit(action = "UPDATE", resourceType = "ROLE", resourceId = "#result.id")
    // 修改角色：PUT /api/roles/{roleCode}
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @PutMapping("/{roleCode}")
    public SysRole edit(
            @PathVariable String roleCode,
            @Validated @RequestBody EditRoleRequest req
    ) {
        SysRole r = roleRepo.findByRoleCode(roleCode)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found"));

        // 允许改的字段
        if (req.roleName != null) r.setRoleName(req.roleName);
        if (req.remark != null) r.setRemark(req.remark);
        r.setStatus(req.status);

        // roleCode 一般不建议改（要改也可以做成单独接口）
        // if (req.roleCode != null) r.setRoleCode(req.roleCode);

        try {
            roleRepo.save(r);
            Long re = roleRepo.save(r).getId();
            List<SysUserRole> predelete = userRoleRepo.findAllByRoleId(re);
            for (SysUserRole u : predelete) {
                redis.delete("auth:perm:"+u.getUserId());
            }
            return r;
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "conflict");
        }
    }

    // 查询角色：GET /api/roles/{roleCode}

    @PreAuthorize("hasAuthority('/**ADMIN')")
    @GetMapping("/{roleCode}")
    public SysRole get(@PathVariable String roleCode) {
        return roleRepo.findByRoleCode(roleCode)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found"));
    }

    // 删除角色：DELETE /api/roles/{roleCode}
    @Audit(action = "DELETE", resourceType = "ROLE", resourceId = "#result.id")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @DeleteMapping("/{roleCode}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public SysRole delete(@PathVariable String roleCode) {
        SysRole r = roleRepo.findByRoleCode(roleCode)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found"));

        Long re = r.getId();
        List<SysUserRole> predelete = userRoleRepo.findAllByRoleId(re);
        for (SysUserRole u : predelete) {
            redis.delete("auth:perm:"+u.getUserId());
        }
        roleRepo.delete(r);
        return r;
    }
}
