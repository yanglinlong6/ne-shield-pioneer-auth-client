package cn.com.glsx.auth.model;

import java.lang.annotation.*;

/**
 * 需要功能权限
 *
 * @author: taoyr
 **/
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface FunctionPermissions {

    FunctionPermissionType permissionType();

}
