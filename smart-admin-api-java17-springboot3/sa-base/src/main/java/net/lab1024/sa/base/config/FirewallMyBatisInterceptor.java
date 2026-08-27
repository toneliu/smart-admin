package net.lab1024.sa.base.config;

import com.firewall.jdbc.FirewallContextHolder;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.plugin.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.Statement;
import java.util.Properties;

/**
 * MyBatis 拦截器：在每条 SQL 执行前，将当前用户身份注入到 MySQL session 变量。
 * <p>
 * 拦截 StatementHandler.prepare(Connection, Integer)，
 * 获取 MyBatis 即将使用的 Connection，执行 SET @firewall_user = 'xxx'。
 * 数据库防火墙可通过该变量识别当前操作者。
 */
@Intercepts({
        @Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class, Integer.class})
})
public class FirewallMyBatisInterceptor implements Interceptor {

    private static final Logger log = LoggerFactory.getLogger(FirewallMyBatisInterceptor.class);

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Connection conn = (Connection) invocation.getArgs()[0];
        String user = FirewallContextHolder.getCurrentUser();
        if (user != null && !user.trim().isEmpty()) {
            String safeUser = user.trim().replaceAll("[^a-zA-Z0-9_\\-]", "");
            if (!safeUser.isEmpty()) {
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("SET @firewall_user = '" + safeUser + "'");
                    log.info("FirewallMyBatisInterceptor: SET @firewall_user = '{}'", safeUser);
                }
            }
        } else {
            log.info("FirewallMyBatisInterceptor: no user in ThreadLocal, skipping SET");
        }
        return invocation.proceed();
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {
    }
}
