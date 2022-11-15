package cn.com.glsx.auth.model;

import lombok.Getter;

/**
 * @author: taoyr
 **/
@Getter
public enum FunctionPermissionType {

    USER_QUERY(1, "usercenter:user:query", "查询用户"),
    USER_ADD(2, "usercenter:user:add", "新增用户"),
    USER_EDIT(3, "usercenter:user:edit", "编辑用户"),
    USER_DELETE(4, "usercenter:user:delete", "删除用户"),

    ROLE_QUERY(1, "usercenter:role:query", "查询角色"),
    ROLE_ADD(2, "usercenter:role:add", "新增角色"),
    ROLE_EDIT(3, "usercenter:role:edit", "编辑角色"),
    ROLE_DELETE(4, "usercenter:role:delete", "删除角色"),

    MENU_QUERY(1, "usercenter:menu:query", "查询菜单"),
    MENU_ADD(2, "usercenter:menu:add", "新增菜单"),
    MENU_EDIT(3, "usercenter:menu:edit", "编辑菜单"),
    MENU_DELETE(4, "usercenter:menu:delete", "删除菜单"),

    ORG_QUERY(1, "usercenter:org:query", "查询组织"),
    ORG_ADD(2, "usercenter:org:add", "新增组织"),
    ORG_EDIT(3, "usercenter:org:edit", "编辑组织"),
    ORG_DELETE(4, "usercenter:org:delete", "删除组织"),

    DEVICE_QUERY(1, "ordercenter:device:query", "查询设备"),
    DEVICE_ADD(2, "ordercenter:device:add", "新增设备"),
    DEVICE_EDIT(3, "ordercenter:device:edit", "编辑设备"),
    DEVICE_DELETE(4, "ordercenter:device:delete", "删除设备"),
    ;

    FunctionPermissionType(int code, String name, String desc) {
        this.code = code;
        this.name = name;
        this.desc = desc;
    }

    /**
     * 权限编号
     */
    private int code;

    /**
     * 权限名
     */
    private String name;

    /**
     * 权限描述
     */
    private String desc;

    public FunctionPermissionType getByCode(int code) {
        FunctionPermissionType[] values = FunctionPermissionType.values();
        for (FunctionPermissionType value : values) {
            if (code == value.code) {
                return value;
            }
        }
        return null;
    }
}
