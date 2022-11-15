package cn.com.glsx.auth.interceptor;

import cn.com.glsx.auth.api.AuthFeignClient;
import cn.com.glsx.auth.model.SyntheticUser;
import cn.com.glsx.auth.utils.ShieldContextHolder;
import com.alibaba.fastjson.JSON;
import com.glsx.plat.core.web.R;
import com.glsx.plat.exception.SystemMessage;
import com.glsx.plat.jwt.base.ComJwtUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * 授权验证拦截器
 *
 * @author payu
 */
@Slf4j
@Component
public class WebRequestAuthorizeInterceptor implements HandlerInterceptor {

    @Value("${spring.application.name}")
    private String application;

    @Autowired
    private AuthFeignClient authFeignClient;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        ShieldContextHolder.setUser(null);
        ShieldContextHolder.removeUser();

        SyntheticUser user = null;

        R<SyntheticUser> r = authFeignClient.getAuthUser();
        if (r.isSuccess()) {
            user = r.getData(SyntheticUser.class);
        }
        if (user != null) {
            ShieldContextHolder.setUser(user);
            return true;
        }
        //需要登录
        needLogin(response);
        return false;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        ShieldContextHolder.setUser(null);
        ShieldContextHolder.removeUser();
    }

    /**
     * 检查token来源
     *
     * @param jwtUser
     * @return
     */
    private boolean checkAccessClient(ComJwtUser jwtUser) {
        if (jwtUser == null) {
            return false;
        }
        return application.equals(jwtUser.getApplication());
    }

    private void needLogin(HttpServletResponse response) throws Exception {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        try (PrintWriter writer = response.getWriter()) {
            writer.write(JSON.toJSONString(R.error(SystemMessage.NOT_LOGIN.getCode(), SystemMessage.NOT_LOGIN.getMsg())));
            writer.flush();
        }
    }

}
