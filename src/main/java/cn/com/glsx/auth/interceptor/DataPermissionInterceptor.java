package cn.com.glsx.auth.interceptor;

import cn.com.glsx.admin.common.constant.UserConstants;
import cn.com.glsx.auth.utils.OriginSqlHolder;
import cn.com.glsx.auth.utils.ShieldContextHolder;
import com.glsx.plat.common.annotation.DataOnlyShared;
import com.glsx.plat.common.annotation.DataPerm;
import com.glsx.plat.common.utils.StringUtils;
import lombok.extern.slf4j.Slf4j;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.parser.CCJSqlParserManager;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.Select;
import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.*;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.io.StringReader;
import java.lang.reflect.Method;
import java.util.Properties;
import java.util.Set;

import static cn.com.glsx.admin.common.constant.UserConstants.RolePermitCastType.*;

/**
 * 处理针对某一或某些特定数据操作（增、删、改、查）作数据权限校验
 * 1、获取用户角色，得到数据权限范围类型
 * 2、得到当前操作用户信息和部门信息
 * 3、根据数据创建者id，得到对应用户或部门
 * 4、比较2，3判断该数据是否有权被操作权限
 *
 * @author: taoyr
 **/
@Slf4j
@SuppressWarnings({"rawtypes", "unchecked"})
@Intercepts(
        {
                @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
                @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class, CacheKey.class, BoundSql.class}),
        }
)
public class DataPermissionInterceptor implements Interceptor {

    @Override
    public Object intercept(Invocation invocation) throws Throwable {

        Object[] args = invocation.getArgs();
        MappedStatement mappedStatement = (MappedStatement) args[0];
        Object parameter = args[1];
        RowBounds rowBounds = (RowBounds) args[2];
        ResultHandler resultHandler = (ResultHandler) args[3];

        Executor executor = (Executor) invocation.getTarget();
        CacheKey cacheKey;
        BoundSql boundSql;
        //由于逻辑关系，只会进入一次
        if (args.length == 4) {
            //4 个参数时
            boundSql = mappedStatement.getBoundSql(parameter);
            cacheKey = executor.createCacheKey(mappedStatement, parameter, rowBounds, boundSql);
        } else {
            //6 个参数时
            cacheKey = (CacheKey) args[4];
            boundSql = (BoundSql) args[5];
        }

        //当前拦截器只处理查询数据权限
        SqlCommandType sqlCommandType = mappedStatement.getSqlCommandType();
        if (sqlCommandType != SqlCommandType.SELECT) {
            return invocation.proceed();
        }

        Method method = getMapperExecutingMethod(mappedStatement);
        if (method == null) {
            return invocation.proceed();
        }

        //如果方法有共享数据注解，直接跳过
        if (method.isAnnotationPresent(DataOnlyShared.class)) {
            return invocation.proceed();
        }

        //没自定义注解直接执行
        if (!method.isAnnotationPresent(DataPerm.class)) {
            return invocation.proceed();
        }

        //超级管理员/全部数据权限 不控制数据权限
        if (ShieldContextHolder.isSuperAdmin() || UserConstants.RolePermitCastType.all.getCode().equals(ShieldContextHolder.getRolePermissionType())) {
            return invocation.proceed();
        }

        DataPerm dataAuth = method.getAnnotation(DataPerm.class);

        //拼装sql
        String originSql = boundSql.getSql(); //获取到当前需要被执行的SQL

        OriginSqlHolder.setSql(originSql);

        String authSql = assemblePermitSql(originSql, dataAuth); //进行数据权限过滤组装
        log.info("\nbaseSql:{}\nauthSql:{}", originSql, authSql);

        // 重新new一个查询语句对像
        BoundSql newBoundSql = new BoundSql(mappedStatement.getConfiguration(), authSql, boundSql.getParameterMappings(), boundSql.getParameterObject());
        // 把新的查询放到statement里
        MappedStatement newMappedStatement = newMappedStatement(mappedStatement, new BoundSqlSqlSource(newBoundSql));
        for (ParameterMapping mapping : boundSql.getParameterMappings()) {
            String prop = mapping.getProperty();
            if (boundSql.hasAdditionalParameter(prop)) {
                newBoundSql.setAdditionalParameter(prop, boundSql.getAdditionalParameter(prop));
            }
        }
        args[0] = newMappedStatement;

        return invocation.proceed();
    }

    /**
     * 将插件对象加入到拦截器链中
     *
     * @param target
     * @return
     */
    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {

    }

    /**
     * 获取当前mapper执行方法
     *
     * @param mappedStatement
     * @return
     * @throws ClassNotFoundException
     */
    private Method getMapperExecutingMethod(MappedStatement mappedStatement) throws ClassNotFoundException {
        String id = mappedStatement.getId();
        String className = id.substring(0, id.lastIndexOf("."));
        String methodName = id.substring(id.lastIndexOf(".") + 1);
        final Method[] method = Class.forName(className).getDeclaredMethods();
        for (Method me : method) {
            if (me.getName().equals(methodName)) {
                return me;
            }
        }
        return null;
    }

    /**
     * 核心代码： 将原SQL 进行解析并拼装 一个子查询  id in ( 数据权限过滤SQL )
     *
     * @param sql
     * @param dataAuth
     * @return
     * @throws JSQLParserException
     */
    private String assemblePermitSql(String sql, DataPerm dataAuth) throws JSQLParserException {
        CCJSqlParserManager parserManager = new CCJSqlParserManager();
        Select select = (Select) parserManager.parse(new StringReader(sql));
        PlainSelect plain = (PlainSelect) select.getSelectBody();

        String permTable = dataAuth.permTable();
        if (StringUtils.isEmpty(permTable)) {
            Table fromItem = (Table) plain.getFromItem();
            //有别名用别名，无别名用表名，防止字段冲突报错
            permTable = fromItem.getAlias() == null ? fromItem.getName() : fromItem.getAlias().getName();
        }

        Set<Long> tenantIds = ShieldContextHolder.getVisibleTenantIds();
        Set<Long> deptIds = ShieldContextHolder.getVisibleDeptIds();
        Set<Long> creatorIds = ShieldContextHolder.getVisibleCreatorIds();

        String linkTable = dataAuth.linkTable();
        String linkField = dataAuth.linkField();

        String tenantIdsStr = StringUtils.join(tenantIds, ',');
        String deptIdsStr = StringUtils.join(deptIds, ',');
        String creatorIdsStr = StringUtils.join(creatorIds, ',');

        String dataAuthSql = "";
        //构建子查询
        Integer rolePermissionType = ShieldContextHolder.getRolePermissionType();
        if (oneself.getCode().equals(rolePermissionType)) {
            dataAuthSql = permTable + ".created_by in (" + creatorIdsStr + ") ";
        } else if (subordinate.getCode().equals(rolePermissionType)) {
            dataAuthSql = permTable + ".created_by in (" + creatorIdsStr + ") ";
        } else if (selfDepartment.getCode().equals(rolePermissionType)) {
            dataAuthSql = permTable + ".created_by in (select " + linkTable + "." + linkField + " from " + linkTable + " where " + linkTable + ".department_id = " + ShieldContextHolder.getDepartmentId() + ") ";
            //dataAuthSql = permTable + ".created_by in (" + creatorIdsStr + ") ";
        } else if (subDepartment.getCode().equals(rolePermissionType)) {
            dataAuthSql = permTable + ".created_by in (select " + linkTable + "." + linkField + " from " + linkTable + " where " + linkTable + ".department_id in (" + deptIdsStr + ")) ";
            //dataAuthSql = permTable + ".created_by in (" + creatorIdsStr + ") ";
        } else if (all.getCode().equals(rolePermissionType)) {
            //do nothing
        } else if (assignTenants.getCode().equals(rolePermissionType)) {
            dataAuthSql = permTable + ".created_by in (select " + linkTable + "." + linkField + " from " + linkTable + " where " + linkTable + ".tenant_id in (" + tenantIdsStr + ")) ";
            //dataAuthSql = permTable + ".created_by in (" + creatorIdsStr + ") ";
        }


        //构建子查询
        if (plain.getWhere() == null) {
            plain.setWhere(CCJSqlParserUtil.parseCondExpression(dataAuthSql));
        } else {
            plain.setWhere(new AndExpression(plain.getWhere(), CCJSqlParserUtil.parseCondExpression(dataAuthSql)));
        }
        return select.toString();
    }

    private MappedStatement newMappedStatement(MappedStatement ms, SqlSource newSqlSource) {
        MappedStatement.Builder builder = new MappedStatement.Builder(ms.getConfiguration(), ms.getId(), newSqlSource, ms.getSqlCommandType());
        builder.resource(ms.getResource());
        builder.fetchSize(ms.getFetchSize());
        builder.statementType(ms.getStatementType());
        builder.keyGenerator(ms.getKeyGenerator());
        if (ms.getKeyProperties() != null && ms.getKeyProperties().length != 0) {
            StringBuilder keyProperties = new StringBuilder();
            for (String keyProperty : ms.getKeyProperties()) {
                keyProperties.append(keyProperty).append(",");
            }
            keyProperties.delete(keyProperties.length() - 1, keyProperties.length());
            builder.keyProperty(keyProperties.toString());
        }
        builder.timeout(ms.getTimeout());
        builder.parameterMap(ms.getParameterMap());
        builder.resultMaps(ms.getResultMaps());
        builder.resultSetType(ms.getResultSetType());
        builder.cache(ms.getCache());
        builder.flushCacheRequired(ms.isFlushCacheRequired());
        builder.useCache(ms.isUseCache());
        return builder.build();
    }

    private class BoundSqlSqlSource implements SqlSource {
        private BoundSql boundSql;

        public BoundSqlSqlSource(BoundSql boundSql) {
            this.boundSql = boundSql;
        }

        @Override
        public BoundSql getBoundSql(Object parameterObject) {
            return boundSql;
        }
    }

}