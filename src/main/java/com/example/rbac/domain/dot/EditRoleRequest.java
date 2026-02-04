package com.example.rbac.domain.dot;

public class EditRoleRequest {
    public String roleCode;   // 必填：用它定位要改哪个角色
    public String roleName;   // 可选
    public String remark;     // 可选
    public Byte status;       // 可选：0/1
}
