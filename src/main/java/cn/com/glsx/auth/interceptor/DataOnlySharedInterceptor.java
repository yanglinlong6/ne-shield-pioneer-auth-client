package cn.com.glsx.auth.interceptor;

import cn.com.glsx.admin.common.constant.UserConstants;
import cn.com.glsx.auth.utils.OriginSqlHolder;
import cn.com.glsx.auth.utils.ShieldContextHolder;
import com.alibaba.nacos.common.utils.CollectionUtils;
import com.glsx.plat.common.annotation.DataOnlyShared;
import com.glsx.plat.common.utils.StringUtils;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.expression.Alias;
import net.sf.jsqlparser.expression.Expression;
import net.sf.jsqlparser.expression.ExpressionVisitorAdapter;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.expression.operators.relational.EqualsTo;
import net.sf.jsqlparser.parser.CCJSqlParserManager;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.schema.Column;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.select.*;
import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.*;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;

import java.io.StringReader;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

/**
 * 二期后面绝对权限,分享的业务数据权限控制（读、写）
 *
 * @author payu
 */
@Slf4j
@SuppressWarnings({"rawtypes", "unchecked"})
@Intercepts(
        {
                @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
                @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class, CacheKey.class, BoundSql.class}),
        }
)
public class DataOnlySharedInterceptor implements Interceptor {

    private static final CCJSqlParserManager parserManager = new CCJSqlParserManager();


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

        //没自定义注解直接按通过
        DataOnlyShared dataAuth = getAnnotation(mappedStatement);
        if (dataAuth == null) {
            return invocation.proceed();
        }

        //超级管理员/全部数据权限 不控制数据权限
        if (ShieldContextHolder.isSuperAdmin() || UserConstants.RolePermitCastType.all.getCode().equals(ShieldContextHolder.getRolePermissionType())) {
            return invocation.proceed();
        }

        //拼装sql
        String originSql = boundSql.getSql(); //获取到当前需要被执行的SQL

        String linkPermitSql = assembleLinkPermitSql(originSql, dataAuth, ShieldContextHolder.getUserId()); //绝对数据权限过滤组装

        if (dataAuth.showSql()) {
            log.info("\noriginSql:{}\nlinkPermitSql:{}", originSql, linkPermitSql);
        }

        //复制一份参数
        if (CollectionUtils.isNotEmpty(boundSql.getParameterMappings())) {
            boundSql.getParameterMappings().addAll(boundSql.getParameterMappings());
        }

        // 重新new一个查询语句对像
        BoundSql newBoundSql = new BoundSql(mappedStatement.getConfiguration(), linkPermitSql, boundSql.getParameterMappings(), boundSql.getParameterObject());
        // 把新的查询放到statement里
        MappedStatement newMappedStatement = newMappedStatement(mappedStatement, new BoundSqlSqlSource(newBoundSql));
        for (ParameterMapping mapping : boundSql.getParameterMappings()) {
            String prop = mapping.getProperty();
            if (boundSql.hasAdditionalParameter(prop)) {
                newBoundSql.setAdditionalParameter(prop, boundSql.getAdditionalParameter(prop));
            }
        }
        args[0] = newMappedStatement;

        OriginSqlHolder.removeSql();

        return invocation.proceed();
    }

    private String assembleLinkPermitSql(String sql, DataOnlyShared dataAuth, Long userId) throws JSQLParserException {

        Select select = (Select) parserManager.parse(new StringReader(sql));

        SelectBody selectBody = select.getSelectBody();

        PlainSelect plain = (PlainSelect) selectBody;

        FromItem fromItem = plain.getFromItem();

        //用表名，不能用表名
        Table table = (Table) fromItem;
        //只能用表名，不能用表名
        String mainTableName = table.getAlias() == null ? table.getName() : table.getAlias().getName();

        String permitTable;
        if (StringUtils.isNotEmpty(dataAuth.linkTable())) {//指定表名
            permitTable = dataAuth.linkTable() + dataAuth.permSuffix();
        } else {
            permitTable = table.getName() + dataAuth.permSuffix();
        }

        //增加join语句
        addJoinMethod(dataAuth.linkField(), plain, mainTableName, permitTable);

        //处理where条件
        handleWhereCriterial(userId, plain, mainTableName, permitTable, table.getAlias() == null);

        String plainStr = plain.toString();

        return plainStr;
    }

    /**
     * 增加join语句
     *
     * @param accessField
     * @param plain
     * @param mainTableName
     * @param permitTable
     */
    private void addJoinMethod(String accessField, PlainSelect plain, String mainTableName, String permitTable) {
        Join join = new Join();
        join.setRight(true);
        join.setRightItem(new Table(permitTable));
        EqualsTo appendExpression = new EqualsTo();
        appendExpression.setLeftExpression(new Column(mainTableName + "." + accessField));
        appendExpression.setRightExpression(new Column(permitTable + ".content_id"));
        join.setOnExpression(appendExpression);

        if (CollectionUtils.isNotEmpty(plain.getJoins())) {
            plain.getJoins().add(join);
        } else {
            plain.setJoins(Lists.newArrayList(join));
        }
    }

    /**
     * 处理where条件
     *
     * @param userId
     * @param plain
     * @param mainTableName
     * @param permitTable
     * @throws JSQLParserException
     */
    private void handleWhereCriterial(Long userId, PlainSelect plain, String mainTableName, String permitTable, boolean addTableAlias) throws JSQLParserException {
        Expression where = plain.getWhere();

        String dataAuthSql = permitTable + ".receiver_id = " + userId + " and " + permitTable + ".del_flag = 0 ";
        if (where == null) {
            plain.setWhere(CCJSqlParserUtil.parseCondExpression(dataAuthSql));
        } else {
            //如果没用别名，需要追加，防止列名冲突
            if (addTableAlias) {
                addTableAliasToColumns(mainTableName, plain);
            }
            plain.setWhere(new AndExpression(where, CCJSqlParserUtil.parseCondExpression(dataAuthSql)));
        }
    }

    /**
     * 处理排序条件
     *
     * @param plain
     * @param mainTableName
     * @param addTableAlias
     * @throws JSQLParserException
     */
    private void handleOrderCriterial(PlainSelect plain, String mainTableName, boolean addTableAlias) throws JSQLParserException {
        List<OrderByElement> orderByElements = plain.getOrderByElements();
        if (CollectionUtils.isNotEmpty(orderByElements)) {
            for (OrderByElement orderByElement : orderByElements) {
                Expression expression = orderByElement.getExpression();
                String orderCol = expression.toString();
                if (addTableAlias) {
                    orderCol = mainTableName + "." + orderCol;
                }
                orderByElement.setExpression(CCJSqlParserUtil.parseCondExpression(orderCol));
            }
        }
    }

    /**
     * 处理排序条件
     *
     * @param plain
     * @param mainTableName
     * @throws JSQLParserException
     */
    private void replaceOrderCriterial(PlainSelect plain, String mainTableName) throws JSQLParserException {

        Map<String, String> columnAliasMap = getSelectItemMap(plain);

        List<OrderByElement> orderByElements = plain.getOrderByElements();
        if (CollectionUtils.isNotEmpty(orderByElements)) {
            for (OrderByElement orderByElement : orderByElements) {
                if (orderByElement.getExpression() instanceof Column) {
                    Column column = (Column) orderByElement.getExpression();
                    String exp = getFullColumn(column);
                    String val = columnAliasMap.get(exp);
                    if (StringUtils.isNotEmpty(val)) {
                        if (orderByElement.isAscDescPresent()) {
                            orderByElement.setExpression(CCJSqlParserUtil.parseCondExpression(val + " DESC"));
                        } else {
                            orderByElement.setExpression(CCJSqlParserUtil.parseCondExpression(val));
                        }
                    }
                }
            }
        }
    }

    private Map<String, String> getSelectItemMap(PlainSelect plain) {
        Map<String, String> itemMap = Maps.newLinkedHashMap();
        List<SelectItem> selectItems = plain.getSelectItems();
        selectItems.forEach(selectItem -> {
            SelectExpressionItem item = (SelectExpressionItem) selectItem;
            if (item.getExpression() instanceof Column) {
                Column column = (Column) item.getExpression();
                Alias alias = item.getAlias();
                String exp = getFullColumn(column);
                itemMap.put(exp, alias != null ? alias.getName() : column.getColumnName());
            }
        });
        return itemMap;
    }

    private String getFullColumn(Column column) {
        String exp = column.getColumnName();
        Table table = column.getTable();
        if (table != null) {
            exp = table.getName() + "." + column.getColumnName();
        }
        return exp;
    }

    /**
     * 修改字段名称
     *
     * @param tableName
     * @param plainSelect
     */
    private void addTableAliasToColumns(String tableName, PlainSelect plainSelect) {
        plainSelect.getWhere().accept(new ExpressionVisitorAdapter() {
            @Override
            public void visit(Column column) {
                column.setColumnName(tableName + "." + column.getColumnName());
            }
        });
    }

    /**
     * 获取方法上的数据权限注解
     *
     * @param mappedStatement
     * @return
     * @throws ClassNotFoundException
     */
    private DataOnlyShared getAnnotation(MappedStatement mappedStatement) throws ClassNotFoundException {
        DataOnlyShared dataAuth = null;
        String id = mappedStatement.getId();
        String className = id.substring(0, id.lastIndexOf("."));
        String methodName = id.substring(id.lastIndexOf(".") + 1);
        final Method[] method = Class.forName(className).getDeclaredMethods();
        for (Method me : method) {
            if (me.getName().equals(methodName) && me.isAnnotationPresent(DataOnlyShared.class)) {
                dataAuth = me.getAnnotation(DataOnlyShared.class);
                break;
            }
        }
        return dataAuth;
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
