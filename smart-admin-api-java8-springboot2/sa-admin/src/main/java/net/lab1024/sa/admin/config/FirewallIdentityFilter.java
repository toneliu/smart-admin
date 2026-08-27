package net.lab1024.sa.admin.config;

import cn.dev33.satoken.stp.StpUtil;
import com.firewall.jdbc.FirewallContextHolder;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 防火墙身份注入过滤器
 *
 * 在所有 Controller / Service / DAO 执行之前，从 Sa-Token 会话中读取当前登录用户 ID
 * （StpUtil.getLoginId()）并写入 FirewallContextHolder ThreadLocal，
 * 使得 FirewallDriver.connect() 建立数据库连接时能将用户身份透传给数据库防火墙。
 *
 * 无论请求成功/失败/异常，finally 中都会调用 clear() 防止 Tomcat 线程池
 * 复用线程时用户身份串号及 ThreadLocal 内存泄漏。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class FirewallIdentityFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            if (request instanceof HttpServletRequest) {
                try {
                    if (StpUtil.isLogin()) {
                        Object loginId = StpUtil.getLoginId();
                        if (loginId != null) {
                            FirewallContextHolder.setCurrentUser(String.valueOf(loginId));
                        }
                    }
                } catch (Exception ignored) {
                    // Sa-Token 未登录会抛异常，忽略；未登录场景 FirewallDriver 会打 warn 并降级
                }
            }
            chain.doFilter(request, response);
        } finally {
            FirewallContextHolder.clear();
        }
    }
}
