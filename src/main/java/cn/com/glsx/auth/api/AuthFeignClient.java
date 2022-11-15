package cn.com.glsx.auth.api;

import cn.com.glsx.auth.model.MenuPermission;
import cn.com.glsx.auth.model.SimpleUser;
import cn.com.glsx.auth.model.SyntheticUser;
import com.glsx.plat.core.web.R;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Set;

/**
 * @author payu
 */
@FeignClient(name = "glsx-ne-shield-usercenter", contextId = "authcenter", path = "/usercenter/auth/")
public interface AuthFeignClient {

    /**
     * 内部登录
     *
     * @return
     */
    @GetMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<SimpleUser> login(@RequestParam("account") String account, @RequestParam("password") String password);

    /**
     * 通过用户id获取用户
     *
     * @param userId
     * @return
     */
    @GetMapping(value = "/loginById", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<SimpleUser> getSimpleUserById(@RequestParam("userId") Long userId);

    /**
     * 嗅探token是否有效(走feign不走网关，走网关网关直接验证了，当需要判断token状态是否有效，可能会使用此接口)
     *
     * @return
     */
    @GetMapping(value = "/sniff", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<Boolean> sniff();

    /**
     * 获取当前登录用户对应资源等权限
     *
     * @return
     */
    @GetMapping(value = "/getAuthUser", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<SyntheticUser> getAuthUser();

    /**
     * 获取userId用户对应资源等权限
     *
     * @return
     */
    @GetMapping(value = "/getAuthUserById", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<SyntheticUser> getAuthUserById(@RequestParam("userId") Long userId);

    /**
     * 获取当前登录用户角色数据权限内的部门id
     *
     * @return
     */
    @GetMapping(value = "/getAuthDeptIds", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<Set<Long>> getAuthDeptIds();

    /**
     * 获取当前登录用户角色数据权限内的用户id
     *
     * @return
     */
    @GetMapping(value = "/getAuthUserIds", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<Set<Long>> getAuthUserIds();

    /**
     * 获取当前登录用户角色授权的功能菜单
     *
     * @return
     */
    @GetMapping(value = "/getPermMenus", consumes = MediaType.APPLICATION_JSON_VALUE)
    R<List<MenuPermission>> getPermMenus();

}
