package com.example.rbac.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(
        name = "sys_role_permission",
        uniqueConstraints = @UniqueConstraint(name = "uk_role_perm", columnNames = {"role_id", "perm_id"}),
        indexes = {
                @Index(name = "idx_rp_role", columnList = "role_id"),
                @Index(name = "idx_rp_perm", columnList = "perm_id")
        }
)
public class SysRolePermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_id", nullable = false)
    private Long roleId;

    @Column(name = "perm_id", nullable = false)
    private Long permId;

    @Column(name = "created_at", nullable = false, updatable = false, insertable = false)
    private LocalDateTime createdAt;
}
