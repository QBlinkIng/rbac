package com.example.rbac.domain.dot;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

public class CreateUserRequest {
    public String username;
    public String password;
    public String nickname;
    public String email;
    public String phone;
}
