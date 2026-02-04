package com.example.rbac.repository;

import com.example.rbac.domain.*;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SysPermissionRepository extends JpaRepository<SysPermission, Long> {
    Optional<SysPermission> findByPermissionCode(String permissionCode);
    Optional<SysPermission> findById(Long Id);
    boolean existsByPermissionCode(String username);
}
