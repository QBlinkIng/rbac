-- V1__init.sql
-- Minimal RBAC schema for MySQL 8.x

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- 1) 用户表
CREATE TABLE IF NOT EXISTS sys_user (
                                        id            BIGINT NOT NULL AUTO_INCREMENT,
                                        username      VARCHAR(64) NOT NULL,
    password_hash VARCHAR(100) NOT NULL,     -- BCrypt/Argon2 hash
    nickname      VARCHAR(64) NULL,
    email         VARCHAR(128) NULL,
    phone         VARCHAR(32) NULL,
    status        TINYINT NOT NULL DEFAULT 1, -- 1=启用 0=禁用
    locked        TINYINT NOT NULL DEFAULT 0, -- 1=锁定
    last_login_at DATETIME(3) NULL,
    created_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_username (username),
    KEY idx_user_status (status),
    KEY idx_user_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 2) 角色表
CREATE TABLE IF NOT EXISTS sys_role (
                                        id          BIGINT NOT NULL AUTO_INCREMENT,
                                        role_code   VARCHAR(64) NOT NULL,        -- 如: ADMIN / USER_MANAGER
    role_name   VARCHAR(64) NOT NULL,        -- 展示名
    status      TINYINT NOT NULL DEFAULT 1,
    remark      VARCHAR(255) NULL,
    created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_code (role_code),
    KEY idx_role_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 3) 权限表（接口/功能权限统一用 code 表达）
CREATE TABLE IF NOT EXISTS sys_permission (
                                              id          BIGINT NOT NULL AUTO_INCREMENT,
                                              perm_code   VARCHAR(128) NOT NULL,       -- 如: user:read / user:create
    perm_name   VARCHAR(128) NOT NULL,
    perm_type   VARCHAR(32) NOT NULL DEFAULT 'API', -- API/MENU/BUTTON（先留着）
    http_method VARCHAR(16) NULL,            -- GET/POST...
    path        VARCHAR(255) NULL,           -- /api/users/**
    status      TINYINT NOT NULL DEFAULT 1,
    remark      VARCHAR(255) NULL,
    created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_perm_code (perm_code),
    KEY idx_perm_type (perm_type),
    KEY idx_perm_path (path)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 4) 用户-角色关联表
CREATE TABLE IF NOT EXISTS sys_user_role (
                                             id        BIGINT NOT NULL AUTO_INCREMENT,
                                             user_id   BIGINT NOT NULL,
                                             role_id   BIGINT NOT NULL,
                                             created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_role (user_id, role_id),
    KEY idx_ur_user (user_id),
    KEY idx_ur_role (role_id),
    CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 5) 角色-权限关联表
CREATE TABLE IF NOT EXISTS sys_role_permission (
                                                   id        BIGINT NOT NULL AUTO_INCREMENT,
                                                   role_id   BIGINT NOT NULL,
                                                   perm_id   BIGINT NOT NULL,
                                                   created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_perm (role_id, perm_id),
    KEY idx_rp_role (role_id),
    KEY idx_rp_perm (perm_id),
    CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
    CONSTRAINT fk_rp_perm FOREIGN KEY (perm_id) REFERENCES sys_permission(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 6) 审计日志表（里程碑1先做基础字段，后面再扩展 diff/trace 等）
CREATE TABLE IF NOT EXISTS sys_audit_log (
                                             id            BIGINT NOT NULL AUTO_INCREMENT,
                                             trace_id      VARCHAR(64) NULL,
    user_id       BIGINT NULL,
    username      VARCHAR(64) NULL,
    action        VARCHAR(64) NOT NULL,       -- CREATE/UPDATE/DELETE/LOGIN...
    resource_type VARCHAR(64) NULL,           -- USER/ROLE/PERMISSION...
    resource_id   VARCHAR(64) NULL,
    http_method   VARCHAR(16) NULL,
    path          VARCHAR(255) NULL,
    ip            VARCHAR(64) NULL,
    user_agent    VARCHAR(512) NULL,
    request_json  JSON NULL,
    diff_json     JSON NULL,
    success       TINYINT NOT NULL DEFAULT 1, -- 1成功 0失败
    error_msg     VARCHAR(512) NULL,
    created_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_audit_created (created_at),
    KEY idx_audit_user (user_id),
    KEY idx_audit_action (action)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET FOREIGN_KEY_CHECKS = 1;
