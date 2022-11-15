package cn.com.glsx.auth.utils;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class OriginSqlHolder {

    private static final ThreadLocal<String> SQL_THREAD_LOCAL = new ThreadLocal<>();

    public static void setSql(String sql) {
        SQL_THREAD_LOCAL.set(sql);
    }

    public static String getSql() {
        String sql = SQL_THREAD_LOCAL.get();
        return sql;
    }

    public static void removeSql() {
        SQL_THREAD_LOCAL.remove();
    }

}
