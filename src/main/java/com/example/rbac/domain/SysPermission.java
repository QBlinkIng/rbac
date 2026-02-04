package com.example.rbac.domain;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;
@Getter
@Setter
@Entity
@Table(name="sys_permission")
public class SysPermission {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @Column(name = "perm_code", nullable = false,unique = true)
    private String permissionCode;
    @Column(name = "perm_name")
    private String permissionName;
    @Column(name = "perm_type")
    private String permissionType;
    @Column(name = "http_method")
    private String httpMethod;
    @Column(name = "path")
    private String path;
    @Column(name = "status")
    private Byte status;
    @Column(name = "remark")
    private String remark;
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
