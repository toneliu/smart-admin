package net.lab1024.sa.base.config;

import com.firewall.jdbc.FirewallContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.datasource.DelegatingDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * 数据源包装类：在每次从连接池获取连接时，将当前用户身份注入到 MySQL session 变量
 * <p>
 * 解决连接池场景下 FirewallDriver.connect() 仅在创建连接时调用、
 * 后续请求复用池中连接导致用户身份无法透传的问题。
 * <p>
 * 通过 SET @firewall_user = 'xxx' 在每次 getConnection 时设置 session 变量，
 * 数据库防火墙可通过该变量识别当前操作者。
 */
public class ConnectionIdentityDataSource extends DelegatingDataSource {

    private static final Logger log = LoggerFactory.getLogger(ConnectionIdentityDataSource.class);

    public ConnectionIdentityDataSource(DataSource delegate) {
        super(delegate);
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection conn = super.getConnection();
        injectFirewallUser(conn);
        return conn;
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        Connection conn = super.getConnection(username, password);
        injectFirewallUser(conn);
        return conn;
    }

    /**
     * 将 ThreadLocal 中的用户身份注入到当前连接的 session 变量
     */
    private void injectFirewallUser(Connection conn) throws SQLException {
        String user = FirewallContextHolder.getCurrentUser();
        log.info("ConnectionIdentityDataSource.getConnection: ThreadLocal user={}", user);
        if (user != null && !user.trim().isEmpty()) {
            // 过滤非法字符，防止 SQL 注入
            String safeUser = user.trim().replaceAll("[^a-zA-Z0-9_\\-]", "");
            if (!safeUser.isEmpty()) {
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("SET @firewall_user = '" + safeUser + "'");
                }
            }
        }
    }
}
