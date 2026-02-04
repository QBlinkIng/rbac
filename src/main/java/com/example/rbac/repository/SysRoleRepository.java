package com.example.rbac.repository;

import com.example.rbac.domain.SysRole;
import com.example.rbac.domain.SysUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SysRoleRepository extends JpaRepository<SysRole, Long> {
    Optional<SysRole> findByRoleName(String roleName);
    Optional<SysRole> findByRoleCode(String roleCode);
    boolean existsByRoleName(String roleName);
}
