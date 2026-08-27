package net.lab1024.sa.admin.config;

import jakarta.annotation.Resource;
import net.lab1024.sa.admin.interceptor.AdminInterceptor;
import net.lab1024.sa.admin.interceptor.FirewallIdentityInterceptor;
import net.lab1024.sa.base.config.SwaggerConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * web相关配置
 *
 * @Author 1024创新实验室-主任: 卓大
 * @Date 2021-09-02 20:21:10
 * @Wechat zhuoda1024
 * @Email lab1024@163.com
 * @Copyright <a href="https://1024lab.net">1024创新实验室</a>
 */
@Configuration
public class MvcConfig implements WebMvcConfigurer {

    @Resource
    private AdminInterceptor adminInterceptor;

    @Resource
    private FirewallIdentityInterceptor firewallIdentityInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 先设置防火墙身份，再执行 AdminInterceptor 鉴权
        registry.addInterceptor(firewallIdentityInterceptor)
                .addPathPatterns("/**");
        registry.addInterceptor(adminInterceptor)
                .excludePathPatterns(SwaggerConfig.SWAGGER_WHITELIST)
                .addPathPatterns("/**");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("doc.html").addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");
    }

}
