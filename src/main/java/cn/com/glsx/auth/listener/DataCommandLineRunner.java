package cn.com.glsx.auth.listener;

import cn.com.glsx.auth.interceptor.DataOnlySharedInterceptor;
import cn.com.glsx.auth.interceptor.DataPermissionInterceptor;
import cn.com.glsx.auth.interceptor.DataPermitLinkInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.session.SqlSessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 此类为了控制mybatis Interceptor执行的顺序，Interceptor调用顺序为后加入的先执行
 */
@Slf4j
@Order
@Component
public class DataCommandLineRunner implements CommandLineRunner {

    @Autowired
    private List<SqlSessionFactory> sqlSessionFactoryList;

    @Override
    public void run(String... args) throws Exception {
        log.info("CommandLineRunner DataPermissionInterceptor init...");
        //先加的后执行
        for (SqlSessionFactory sqlSessionFactory : sqlSessionFactoryList) {

            sqlSessionFactory.getConfiguration().addInterceptor(new DataPermitLinkInterceptor());
            sqlSessionFactory.getConfiguration().addInterceptor(new DataPermissionInterceptor());
            sqlSessionFactory.getConfiguration().addInterceptor(new DataOnlySharedInterceptor());

            List<Interceptor> interceptorList = sqlSessionFactory.getConfiguration().getInterceptors();
            interceptorList.forEach(interceptor -> {
                log.info(interceptor.getClass().getSimpleName());
            });
        }
    }
}
