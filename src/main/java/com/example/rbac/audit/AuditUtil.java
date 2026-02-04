package com.example.rbac.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;

public class AuditUtil {

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password", "pwd", "token", "authorization", "accessToken", "refreshToken", "secret"
    );

    private AuditUtil() {}

    public static String getClientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String realIp = req.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) return realIp;
        return req.getRemoteAddr();
    }

    public static String safeArgsJson(ObjectMapper om, Object[] args) {
        try {
            List<Object> sanitized = new ArrayList<>();
            for (Object a : args) {
                if (a == null) continue;
                // 过滤掉 request/response/file 等不适合记录的对象
                if (a instanceof HttpServletRequest) continue;
                if (a instanceof jakarta.servlet.http.HttpServletResponse) continue;
                if (a instanceof MultipartFile) continue;

                sanitized.add(maskObject(a));
            }
            return om.writeValueAsString(sanitized);
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Object maskObject(Object o) {
        if (o instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (var entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                Object val = entry.getValue();
                if (SENSITIVE_KEYS.contains(key)) copy.put(key, "***");
                else copy.put(key, maskObject(val));
            }
            return copy;
        }
        if (o instanceof Collection<?> c) {
            List<Object> out = new ArrayList<>();
            for (Object item : c) out.add(maskObject(item));
            return out;
        }
        // 简化：其它对象交给 Jackson；真正严格脱敏可在里程碑2增强
        return o;
    }

    public static String trim(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }
}
