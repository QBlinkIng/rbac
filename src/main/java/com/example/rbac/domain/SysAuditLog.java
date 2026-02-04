package com.example.rbac.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "sys_audit_log")
@Getter
@Setter
public class SysAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "trace_id", length = 64)
    private String traceId;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "username", length = 64)
    private String username;

    @Column(name = "action", nullable = false, length = 64)
    private String action;

    @Column(name = "resource_type", length = 64)
    private String resourceType;

    @Column(name = "resource_id", length = 64)
    private String resourceId;

    @Column(name = "http_method", length = 16)
    private String httpMethod;

    @Column(name = "path", length = 255)
    private String path;

    @Column(name = "ip", length = 64)
    private String ip;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    /**
     * 对应 MySQL JSON 字段
     * 这里用 String 存 JSON 文本，写入时自己用 ObjectMapper 序列化即可
     */
    @Lob
    @Column(name = "request_json", columnDefinition = "json")
    private String requestJson;

    @Lob
    @Column(name = "diff_json", columnDefinition = "json")
    private String diffJson;

    /**
     * 1成功 0失败
     */
    @Column(name = "success", nullable = false)
    private Byte success = 1;

    @Column(name = "error_msg", length = 512)
    private String errorMsg;

    /**
     * created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)
     * 让 DB 默认值生效也可以；这里用 Hibernate 自动填充更方便
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
