package net.lab1024.sa.admin.interceptor;

import cn.dev33.satoken.stp.StpUtil;
import com.firewall.jdbc.FirewallContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 身份拦截器：在 HandlerInterceptor 层提取 Sa-Token 用户 ID 并写入 ThreadLocal。
 * <p>
 * 使用 HandlerInterceptor 而非 Filter，因为 Sa-Token 上下文在 DispatcherServlet
 * 内才完全初始化，Filter 层调用 StpUtil 会抛 "上下文尚未初始化"。
 */
@Component
public class FirewallIdentityInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(FirewallIdentityInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            if (StpUtil.isLogin()) {
                Object loginId = StpUtil.getLoginId();
                if (loginId != null) {
                    FirewallContextHolder.setCurrentUser(String.valueOf(loginId));
                    log.info("FirewallIdentityInterceptor: user={} set to ThreadLocal", loginId);
                }
            }
        } catch (Exception e) {
            log.warn("FirewallIdentityInterceptor: StpUtil exception: {}", e.getMessage());
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        FirewallContextHolder.clear();
    }
}
