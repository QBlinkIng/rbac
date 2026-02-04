package com.example.rbac.domain.dot;


public class EditPermissionRequest {
    public String permissionCode;      // 必填：定位要改哪个
    public String permissionName;      // 可选：改名
    public String permissionType;      // 可选
    public String httpMethod;          // 可选
    public String path;                // 可选
    public String remark;              // 可选
    public Byte status;                // 可选：0/1
}
