package com.example.rbac.audit;

import com.example.rbac.domain.SysAuditLog;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.MDC;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;

@Aspect
@Component
public class AuditAspect {

    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    private final ExpressionParser spel = new SpelExpressionParser();
    private final DefaultParameterNameDiscoverer nameDiscoverer = new DefaultParameterNameDiscoverer();

    public AuditAspect(AuditLogService auditLogService, ObjectMapper objectMapper) {
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    @Around("@annotation(audit)")
    public Object around(ProceedingJoinPoint pjp, Audit audit) throws Throwable {
        SysAuditLog log = new SysAuditLog();
        log.setAction(audit.action());
        log.setResourceType(audit.resourceType());

        // request 相关
        HttpServletRequest req = currentRequest();
        if (req != null) {
            log.setHttpMethod(req.getMethod());
            log.setPath(req.getRequestURI());
            log.setIp(AuditUtil.getClientIp(req));
            log.setUserAgent(AuditUtil.trim(req.getHeader("User-Agent"), 512));
        }

        // trace_id
        log.setTraceId(MDC.get("traceId"));

        // user 相关
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            log.setUsername(auth.getName());
            // 如果你的 principal 里有 userId，可在这里取（先用反射兜底）
            Long uid = null;
            Object details = auth.getDetails();
            if (details instanceof Long l) uid = l;
            log.setUserId(uid);
        }

        // request_json
        if (audit.logArgs()) {
            log.setRequestJson(AuditUtil.trim(AuditUtil.safeArgsJson(objectMapper, pjp.getArgs()), 20000));
        }

        Method method = ((MethodSignature) pjp.getSignature()).getMethod();

        try {
            Object result = pjp.proceed();
            log.setSuccess((byte) 1);

            // resource_id（支持 #result）
            String rid = evalResourceId(audit.resourceId(), method, pjp.getArgs(), result);
            log.setResourceId(rid);

            auditLogService.saveAsync(log);
            return result;
        } catch (Throwable ex) {
            log.setSuccess((byte) 0);
            log.setErrorMsg(AuditUtil.trim(ex.getMessage(), 512));

            String rid = evalResourceId(audit.resourceId(), method, pjp.getArgs(), null);
            log.setResourceId(rid);

            auditLogService.saveAsync(log);
            throw ex;
        }
    }

    private HttpServletRequest currentRequest() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes sra) return sra.getRequest();
        return null;
    }

    private String evalResourceId(String expr, Method method, Object[] args, Object result) {
        if (expr == null || expr.isBlank()) return null;

        String[] paramNames = nameDiscoverer.getParameterNames(method);
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        if (paramNames != null) {
            for (int i = 0; i < paramNames.length; i++) ctx.setVariable(paramNames[i], args[i]);
        }
        for (int i = 0; i < args.length; i++) ctx.setVariable("p" + i, args[i]);
        ctx.setVariable("result", result);

        try {
            Object val = spel.parseExpression(expr).getValue(ctx);
            return val == null ? null : String.valueOf(val);
        } catch (Exception e) {
            return null;
        }
    }

    private Long extractUserId(Object principal) {
        if (principal == null) return null;
        try {
            var m = principal.getClass().getMethod("getId");
            Object id = m.invoke(principal);
            if (id instanceof Long l) return l;
            if (id instanceof Number n) return n.longValue();
        } catch (Exception ignore) {}
        return null;
    }
}
