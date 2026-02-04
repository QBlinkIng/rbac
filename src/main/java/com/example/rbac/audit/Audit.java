package com.example.rbac.audit;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Audit {

    /** 动作：CREATE/UPDATE/DELETE/LOGIN... */
    String action();

    /** 资源类型：USER/ROLE/PERMISSION... */
    String resourceType() default "";

    /**
     * 资源ID（支持 SpEL）
     * 示例：
     *  - "#id"
     *  - "#req.id"
     *  - "#result.id"（适合 create 返回实体/DTO 的场景）
     */
    String resourceId() default "";

    /** 是否记录入参（会做简单脱敏） */
    boolean logArgs() default true;
}
