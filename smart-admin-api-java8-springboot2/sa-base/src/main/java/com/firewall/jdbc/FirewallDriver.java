package com.firewall.jdbc;

import com.mysql.cj.jdbc.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

/**
 * 防火墙 JDBC 包装驱动（集成于 SmartAdmin）
 * 继承 MySQL 原生驱动，在建立连接时从 ThreadLocal 读取当前登录用户 ID，
 * 并通过 connectionAttributes 和自定义属性 firewall_user 透传给数据库防火墙。
 *
 * 使用方式：
 * 1. 业务 JDBC URL 指向防火墙地址（如 jdbc:mysql://firewall-host:13306/smart_admin_v3）
 * 2. 驱动类：com.firewall.jdbc.FirewallDriver（若使用 P6Spy 则设为 realdriver）
 * 3. 请求入口 FirewallIdentityFilter 会从 Sa-Token 取用户 ID 注入 ThreadLocal
 */
public class FirewallDriver extends Driver {

    private static final Logger log = LoggerFactory.getLogger(FirewallDriver.class);

    public static final String CONNECTION_ATTRIBUTES_KEY = "connectionAttributes";
    public static final String FIREWALL_USER_KEY = "firewall_user";
    public static final String ATTR_USER_KEY = "firewall_user";

    /**
     * 显式声明构造器并传播 SQLException，
     * 否则编译器生成的默认构造器会因父类构造器抛出检查异常而编译失败。
     */
    public FirewallDriver() throws SQLException {
        super();
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) {
            return null;
        }
        Properties mergedInfo = (info != null) ? (Properties) info.clone() : new Properties();
        String currentUser = FirewallContextHolder.getCurrentUser();
        if (currentUser != null && !currentUser.trim().isEmpty()) {
            injectUserIdentity(mergedInfo, currentUser.trim());
            log.debug("Injecting firewall user identity to connection: user={}", currentUser);
        } else {
            log.warn("No current user found in FirewallContextHolder. " +
                    "Connection will be established without user identity. " +
                    "Firewall may apply default permissions.");
        }
        return super.connect(url, mergedInfo);
    }

    private void injectUserIdentity(Properties info, String userId) {
        info.setProperty(FIREWALL_USER_KEY, userId);
        String existingAttrs = info.getProperty(CONNECTION_ATTRIBUTES_KEY, "");
        String userAttr = ATTR_USER_KEY + "=" + userId;
        if (existingAttrs.isEmpty()) {
            info.setProperty(CONNECTION_ATTRIBUTES_KEY, userAttr);
        } else {
            if (!existingAttrs.contains(ATTR_USER_KEY + "=")) {
                info.setProperty(CONNECTION_ATTRIBUTES_KEY, existingAttrs + "," + userAttr);
            } else {
                info.setProperty(CONNECTION_ATTRIBUTES_KEY, replaceOrAppendAttribute(existingAttrs, ATTR_USER_KEY, userId));
            }
        }
    }

    private String replaceOrAppendAttribute(String attrs, String key, String newValue) {
        String[] pairs = attrs.split(",");
        StringBuilder result = new StringBuilder();
        boolean found = false;
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            if (i > 0) result.append(",");
            int eqIndex = pair.indexOf('=');
            if (eqIndex > 0 && pair.substring(0, eqIndex).trim().equals(key)) {
                result.append(key).append("=").append(newValue);
                found = true;
            } else {
                result.append(pair);
            }
        }
        if (!found) {
            if (result.length() > 0) result.append(",");
            result.append(key).append("=").append(newValue);
        }
        return result.toString();
    }
}
