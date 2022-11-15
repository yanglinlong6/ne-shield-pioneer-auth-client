package cn.com.glsx.auth.utils;

import cn.com.glsx.auth.model.*;
import lombok.NoArgsConstructor;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author payu
 */
@NoArgsConstructor
public class ShieldContextHolder {

    public static final Long ADMIN_ROLE_ID = 1L;

    private static final ThreadLocal<SyntheticUser> USER_THREAD_LOCAL = new ThreadLocal<>();

    // 获取当前用户
    public static SyntheticUser getUser() {
        SyntheticUser user = USER_THREAD_LOCAL.get();
        Assert.notNull(user, "获取当前用户信息失败");
        return user;
    }

    // 设置当前用户
    public static void setUser(SyntheticUser user) {
        USER_THREAD_LOCAL.set(user);
    }

    // 移除当前用户
    public static void removeUser() {
        USER_THREAD_LOCAL.remove();
    }

    public static boolean isSuperAdmin() {
        return getUser().getIsSupperAdmin();
    }

    public static Long getUserId() {
        return getUser().getUserId();
    }

    public static String getAccount() {
        return getUser().getAccount();
    }

    public static String getUsername() {
        return getUser().getUsername();
    }

//    public static UserGroup getUserGroup() {
//        SyntheticUser user = getUser();
//        return user.getUserGroup();
//    }

    public static Tenant getTenant() {
        SyntheticUser user = getUser();
        Tenant tenant = user.getTenant();
        Assert.notNull(tenant, "获取当前用户租户信息失败");
        return tenant;
    }

    public static Department getDepartment() {
        SyntheticUser user = getUser();
        Department dept = user.getDepartment();
        Assert.notNull(dept, "获取当前用户部门信息失败");
        return dept;
    }

    public static Long getTenantId() {
        return getTenant().getTenantId();
    }

    public static Long getDepartmentId() {
        return getDepartment().getDeptId();
    }

    public static List<Long> getRoleIds() {
        List<Role> roleList = getUser().getRoles();
        if (CollectionUtils.isNotEmpty(roleList)) {
            return roleList.stream().map(Role::getRoleId).collect(Collectors.toList());
        }
        return new ArrayList<>();
    }

    /**
     * 获取当前用户角色数据权限可见的租户id
     *
     * @return
     */
    public static Set<Long> getVisibleTenantIds() {
        return getUser().getVisibleTenantIds();
    }

    /**
     * 获取当前用户角色数据权限可见的部门id
     *
     * @return
     */
    public static Set<Long> getVisibleDeptIds() {
        return getUser().getVisibleDeptIds();
    }

    /**
     * 获取当前用户角色数据权限可见的创建人id
     *
     * @return
     */
    public static Set<Long> getVisibleCreatorIds() {
        return getUser().getVisibleCreatorIds();
    }

    public static Role getRole() {
        Role role = getUser().getRoles().get(0);
        Assert.notNull(role, "获取当前用户角色信息失败");
        return role;
    }

    public static List<BizDataPermission> getRoleBizDataPermissions() {
        Role role = getUser().getRoles().get(0);
        Assert.notNull(role, "获取当前用户角色信息失败");
        return role.getBizDataPermissions();
    }

    public static Long getRoleId() {
        return getRole().getRoleId();
    }

    public static Integer getRoleVisibility() {
        return getRole().getRoleVisibility();
    }

    public static Integer getRolePermissionType() {
        return getRole().getRolePermissionType();
    }

}
