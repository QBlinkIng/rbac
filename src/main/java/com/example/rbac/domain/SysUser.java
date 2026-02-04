package com.example.rbac.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;



@Getter
@Setter

@Entity
@Table(name = "sys_user")
public class SysUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64, unique = true)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    private String nickname;
    private String email;
    private String phone;

    @Column(nullable = false)
    private Byte status;   // 0/1/2...
    // 1启用 0禁用

    @JdbcTypeCode(SqlTypes.TINYINT)
    @Column(nullable = false)
    private Boolean locked;
    // 1锁定 0未锁定

    private LocalDateTime lastLoginAt;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    @PrePersist
    public void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }
    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
    // --- getter/setter 省略（你可以用 Lombok @Getter/@Setter）
    // 但注意 Lombok 需要 IDE 开启 annotation processing
}
