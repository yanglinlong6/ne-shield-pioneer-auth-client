package cn.com.glsx.auth.listener;

import cn.com.glsx.auth.interceptor.DataPermissionInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.session.SqlSessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;

import java.util.List;

@Slf4j
//@Component
public class SqlSessionListener implements ApplicationListener<SqlSessionEvent> {

    @Autowired
    private List<SqlSessionFactory> sqlSessionFactoryList;

    @Override
    public void onApplicationEvent(SqlSessionEvent event) {
        log.info("SqlSessionListener DataPermissionInterceptor init...");
        //先加的后执行
        for (SqlSessionFactory sqlSessionFactory : sqlSessionFactoryList) {
            sqlSessionFactory.getConfiguration().addInterceptor(new DataPermissionInterceptor());
        }
    }

}
