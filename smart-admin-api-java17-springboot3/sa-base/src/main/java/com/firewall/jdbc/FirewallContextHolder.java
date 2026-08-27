package com.firewall.jdbc;

/**
 * 防火墙用户上下文持有者
 * 使用 ThreadLocal 存储当前请求的用户ID，由 FirewallIdentityFilter 负责在请求入口写入、结束时清除，
 * FirewallDriver 在 connect() 时从这里读取并注入到连接属性中。
 */
public class FirewallContextHolder {

    private static final ThreadLocal<String> CURRENT_USER_HOLDER = new ThreadLocal<>();

    private FirewallContextHolder() {
    }

    public static void setCurrentUser(String userId) {
        CURRENT_USER_HOLDER.set(userId);
    }

    public static String getCurrentUser() {
        return CURRENT_USER_HOLDER.get();
    }

    public static void clear() {
        CURRENT_USER_HOLDER.remove();
    }
}
