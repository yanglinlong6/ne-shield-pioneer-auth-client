package cn.com.glsx.auth.model;

import lombok.Data;

import java.util.List;

@Data
public class Role {

    private Long tenantId;

    private Long roleId;

    private String roleName;

    /**
     * 0=共享，1=系统管理员，2=指定租户
     */
    private Integer roleVisibility;

    /**
     * 角色权限类型 0=本人 1=本人及下属 2=本部门 3=本部门及下级部门 4=全部
     */
    private Integer rolePermissionType;

    /**
     * 业务数据
     */
    private List<BizDataPermission> bizDataPermissions;

    /**
     * 菜单权限
     */
    private List<MenuPermission> menuPermissionList;

}
