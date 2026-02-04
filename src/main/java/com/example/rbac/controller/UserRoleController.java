package com.example.rbac.controller;

import com.example.rbac.audit.Audit;
import com.example.rbac.domain.SysRole;
import com.example.rbac.domain.SysUser;
import com.example.rbac.domain.SysUserRole;
import com.example.rbac.domain.dot.CreateUserRoleRequest;
import com.example.rbac.repository.SysRoleRepository;
import com.example.rbac.repository.SysUserRepository;
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
@RequestMapping("/api/admin/user-roles")
@PreAuthorize("hasRole('ADMIN')")
public class UserRoleController {

    private final SysUserRepository userRepo;
    private final SysRoleRepository roleRepo;
    private final SysUserRoleRepository userRoleRepo;

    private final StringRedisTemplate redis;
    public UserRoleController(SysUserRepository userRepo,
                              SysRoleRepository roleRepo,
                              SysUserRoleRepository userRoleRepo, StringRedisTemplate redis) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.userRoleRepo = userRoleRepo;
        this.redis = redis;
    }

    /** 给用户分配角色 */
    @Audit(action = "UPDATE", resourceType = "USER_ROLE", resourceId = "#result.id")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @PostMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public SysUserRole assignRole(@Validated @RequestBody CreateUserRoleRequest req) {
        if (req.userId == null || req.roleId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "userId/roleId required");
        }

        // 1) 校验 user / role 是否存在
        SysUser u = userRepo.findById(req.userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found"));
        SysRole r = roleRepo.findById(req.roleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found"));

        // 2) 创建关联
        SysUserRole ur = new SysUserRole();
        ur.setUserId(u.getId());
        ur.setRoleId(r.getId());
        redis.delete("auth:perm:" + u.getId());
        try {
            userRoleRepo.save(ur);
            return ur;
        } catch (DataIntegrityViolationException e) {
            // uk_user_role 冲突
            throw new ResponseStatusException(HttpStatus.CONFLICT, "user already has this role");
        }
    }

    /** 移除用户角色 */
    @Audit(action = "DELETE", resourceType = "USER_ROLE", resourceId = "#result")
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public long removeRole(@Validated @RequestBody CreateUserRoleRequest req) {
        if (req.userId == null || req.roleId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "userId/roleId required");
        }

        long deleted = userRoleRepo.deleteByUserIdAndRoleId(req.userId, req.roleId);
        if (deleted == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "user-role relation not found");
        }
        redis.delete("auth:perm:" + req.userId);

        return deleted;
    }

    /** 查询某用户所有 roleId（后续再升级成 roleCode/roleName） */
    @PreAuthorize("hasAuthority('/**ADMIN')")
    @GetMapping("/{userId}")
    public List<Long> listRoleIds(@PathVariable Long userId) {
        // 用户不存在就 404（更清晰）
        if (!userRepo.existsById(userId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found");
        }
        return userRoleRepo.findAllByUserId(userId).stream()
                .map(SysUserRole::getRoleId)
                .toList();
    }
}
