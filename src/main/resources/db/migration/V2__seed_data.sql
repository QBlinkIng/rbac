-- 1) 角色
INSERT INTO sys_role (id, role_code, role_name, status, remark, created_at, updated_at)
VALUES
    (1, 'ADMIN', '系统管理员', 1, '内置超级管理员', NOW(), NOW())
    ON DUPLICATE KEY UPDATE updated_at = NOW();

-- 2) 用户（密码先占位，建议你启动后用 Java BCrypt 生成再替换）
-- 这里 password_hash 先写一个占位值，等你生成 BCrypt 后替换 密码：admin123
INSERT INTO sys_user (id, username, password_hash, status, locked, last_login_at, created_at, updated_at)
VALUES
    (1, 'admin', '$2a$10$q4ofAw9N.5XHaxQqXjt0KOlIVjTvJrjGGbmK0NojaJ23M4rIQWyxa', 1, 0, NULL, NOW(), NOW())
    ON DUPLICATE KEY UPDATE updated_at = NOW();

-- 3) 权限点（示例：用户/角色/权限管理）
INSERT INTO sys_permission (id, perm_code, perm_name, perm_type, http_method, path, status, created_at, updated_at)
VALUES
    (1, 'ADMIN',   '最高管理员', 'API', 'ADMIN',    '/**', 1, NOW(), NOW())
    ON DUPLICATE KEY UPDATE updated_at = NOW();

-- 4) 绑定：admin -> ADMIN
INSERT INTO sys_user_role (user_id, role_id, created_at)
VALUES (1, 1, NOW())
    ON DUPLICATE KEY UPDATE created_at = created_at;

-- 5) 绑定：ADMIN -> 所有权限
INSERT INTO sys_role_permission (role_id, perm_id, created_at)
VALUES
    (1, 1, NOW())
    ON DUPLICATE KEY UPDATE created_at = created_at;
