package com.example.rbac.repository;

import com.example.rbac.domain.SysUserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SysUserRoleRepository extends JpaRepository<SysUserRole, Long> {
    boolean existsByUserIdAndRoleId(Long userId, Long roleId);
    Optional<SysUserRole> findByUserIdAndRoleId(Long userId, Long roleId);
    List<SysUserRole> findAllByUserId(Long userId);
    List<SysUserRole> findAllByRoleId(Long roleId);
    long deleteByUserIdAndRoleId(Long userId, Long roleId);
    long deleteAllByUserId(Long userId);
}
