package cn.com.glsx.auth.interceptor;

import cn.com.glsx.auth.api.AuthFeignClient;
import cn.com.glsx.auth.model.FunctionPermissions;
import cn.com.glsx.auth.model.MenuPermission;
import cn.com.glsx.auth.model.SyntheticUser;
import cn.com.glsx.auth.utils.ShieldContextHolder;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.glsx.plat.core.web.R;
import com.glsx.plat.exception.SystemMessage;
import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 功能菜单权限
 *
 * @author: taoyr
 **/
@Slf4j
@Component
public class WebFunctionPermissionInterceptor implements HandlerInterceptor {

    @Autowired
    private AuthFeignClient authFeignClient;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (handler instanceof HandlerMethod) {
            FunctionPermissions permissionRequired = ((HandlerMethod) handler).getMethodAnnotation(FunctionPermissions.class);
            if (permissionRequired == null) {
                return true;
            }

            SyntheticUser currentUser = ShieldContextHolder.getUser();
            if (currentUser == null) {
                return true;
            }

            String uri = request.getRequestURI();
            log.info("RequestURI:" + uri);

            List<MenuPermission> menuPermissionList = Lists.newArrayList();

            R<List<MenuPermission>> r = authFeignClient.getPermMenus();
            if (r.isSuccess()) {
                Object obj = r.getData();
                if (obj instanceof JSONArray) {
                    menuPermissionList = JSON.parseArray(((JSONArray) obj).toJSONString(), MenuPermission.class);
                } else if (obj instanceof ArrayList) {
                    menuPermissionList = (List<MenuPermission>) obj;
                }
            }
            boolean isPermit = menuPermissionList.stream().map(MenuPermission::getInterfaceUrl).collect(Collectors.toList()).contains(uri);
            if (!isPermit) {
                needPermission(response);
                return false;
            }
        }
        return true;
    }

    private void needPermission(HttpServletResponse response) throws Exception {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        try (PrintWriter writer = response.getWriter()) {
            writer.write(JSON.toJSONString(R.error(
                    SystemMessage.OPERATE_PERMISSION_DENIED.getCode(),
                    SystemMessage.OPERATE_PERMISSION_DENIED.getMsg())
            ));
            writer.flush();
        }
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {

    }
}
