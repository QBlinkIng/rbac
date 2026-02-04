package com.example.rbac.audit;

import com.example.rbac.domain.SysAuditLog;

public interface AuditLogService {
    void save(SysAuditLog log);
    void saveAsync(SysAuditLog log);
}

