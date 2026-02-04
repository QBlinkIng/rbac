package com.example.rbac.controller;

import com.example.rbac.audit.Audit;
import com.example.rbac.domain.*;
import com.example.rbac.domain.dot.CreateRolePermRequest;
import com.example.rbac.repository.SysPermissionRepository;
import com.example.rbac.repository.SysRolePermissionRepository;
import com.example.rbac.repository.SysRoleRepository;
import com.example.rbac.repository.SysUserRoleRepository;
import jakarta.transaction.Transactional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
@Transactional
@RestController

@RequestMapping("/api/admin/role-permissions")
public class RolePermissionController {

    private final SysRoleRepository roleRepo;
    private final SysPermissionRepository permRepo;
    private final SysRolePermissionRepository rpRepo;
    private final StringRedisTemplate redis;
    private final SysUserRoleRepository userRoleRepo;
    public RolePermissionController(SysRoleRepository roleRepo,
                                    SysPermissionRepository permRepo,
                                    SysRolePermissionRepository rpRepo, StringRedisTemplate redis, SysUserRoleRepository userRoleRepo) {
        this.roleRepo = roleRepo;
        this.permRepo = permRepo;
        this.rpRepo = rpRepo;
        this.redis = redis;
        this.userRoleRepo = userRoleRepo;
    }

    /** 给角色分配权限 */
    @Audit(action = "CREATE", resourceType = "ROLE_PERMISSION", resourceId = "#result.id")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @PostMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public SysRolePermission grant(@Validated @RequestBody CreateRolePermRequest req) {

        // 1) role/perm 必须存在
        SysRole role = roleRepo.findById(req.roleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found"));
        SysPermission perm = permRepo.findById(req.permId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "permission not found"));

        // 2) 建关联
        SysRolePermission rp = new SysRolePermission();
        rp.setRoleId(role.getId());
        rp.setPermId(perm.getId());
        try {
            rpRepo.save(rp);
            List<SysUserRole> t = userRoleRepo.findAllByRoleId(rp.getRoleId());
            for(SysUserRole u : t) {
                redis.delete("auth:perm:" + u.getUserId());
            }
            return rp;
        } catch (DataIntegrityViolationException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "role already has this permission");
        }
    }

    /** 移除角色权限 */
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @Audit(action = "DELETE", resourceType = "ROLE_PERMISSION", resourceId = "#result")
    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public long revoke(@Validated @RequestBody CreateRolePermRequest req) {
        long deleted = rpRepo.deleteByRoleIdAndPermId(req.roleId, req.permId);
        if (deleted == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "role-permission relation not found");
        }
        List<SysUserRole> t = userRoleRepo.findAllByRoleId(req.roleId);
        for(SysUserRole u : t) {
            redis.delete("auth:perm:" + u.getUserId());
        }
        return deleted;
    }

    /** 查询角色下所有 permId（后续再升级为 perm_code 列表） */
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @GetMapping("/{roleId}")
    public List<Long> listPermIds(@PathVariable Long roleId) {
        if (!roleRepo.existsById(roleId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found");
        }

        return rpRepo.findAllByRoleId(roleId).stream()
                .map(SysRolePermission::getPermId)
                .toList();
    }
}
