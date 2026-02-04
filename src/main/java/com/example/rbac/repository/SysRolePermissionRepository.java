package com.example.rbac.repository;

import com.example.rbac.domain.SysRolePermission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SysRolePermissionRepository extends JpaRepository<SysRolePermission, Long> {
    boolean existsByRoleIdAndPermId(Long roleId, Long permId);
    long deleteByRoleIdAndPermId(Long roleId, Long permId);
    List<SysRolePermission> findAllByRoleId(Long roleId);
    List<SysRolePermission> findAllByPermId(Long permId);
}
