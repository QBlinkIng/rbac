package com.example.rbac.audit;

import com.example.rbac.domain.SysAuditLog;
import com.example.rbac.repository.SysAuditLogRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    private final SysAuditLogRepository repo;

    public AuditLogServiceImpl(SysAuditLogRepository repo) {
        this.repo = repo;
    }

    @Override
    public void save(SysAuditLog log) {
        repo.save(log);
    }

    @Async("auditExecutor")
    @Override
    public void saveAsync(SysAuditLog log) {
        repo.save(log);
    }
}
