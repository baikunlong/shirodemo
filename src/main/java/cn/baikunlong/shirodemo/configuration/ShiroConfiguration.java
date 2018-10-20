package cn.baikunlong.shirodemo.configuration;

import cn.baikunlong.shirodemo.shiro.MyFormAuthenticationFilter;
import cn.baikunlong.shirodemo.shiro.MyReaml;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class ShiroConfiguration {
    /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是或报错的，以为在
     * 初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     * Filter Chain定义说明 1、一个URL可以配置多个Filter，使用逗号分隔 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        //必须设置
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //登陆页面
        shiroFilterFactoryBean.setLoginUrl("/login.html");
        // 登录成功后要跳转的链接,默认是上一个页面
        shiroFilterFactoryBean.setSuccessUrl("/index.html");
        // 未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403.html");

        //将自定义的表单过滤器配置进去
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("authc", new MyFormAuthenticationFilter());
        shiroFilterFactoryBean.setFilters(filterMap);

        HashMap<String, String> map = new HashMap<>();
        map.put("/login.html", "anon");//不需要登陆
        map.put("/login", "anon");//不需要登陆
        map.put("/getCaptcha", "anon");//不需要登陆
        map.put("/logout", "logout");//这个注销要配置，才会跳转到登陆页！！！！！！
        map.put("/index.html","user");//通过记住我可以访问
        map.put("/**", "authc");//需要登陆
        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
//        shiroFilterFactoryBean.setFilterChainDefinitions("/login.html=anon\nlogin=anon\n/getCaptcha=anon\n/**=authc");
        return shiroFilterFactoryBean;
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(myReaml());
        //缓存帮助博客https://www.sojson.com/blog/73.html
        EhCacheManager ehCacheManager = new EhCacheManager();
        ehCacheManager.setCacheManagerConfigFile("classpath:config/shiro-ehcache.xml");
        securityManager.setCacheManager(ehCacheManager);
        //sessionManager
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setDeleteInvalidSessions(true);//删除失效的session
        sessionManager.setGlobalSessionTimeout(1000 * 60 * 15);//失效时间
        sessionManager.setSessionIdCookie(new SimpleCookie("freeway.session.id"));
        securityManager.setSessionManager(sessionManager);
        //rememberMeManager
        securityManager.setRememberMeManager(rememberMeManager());
        return securityManager;
    }

    @Bean
    public SimpleCookie rememberMeCookie(){
        //这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        //<!-- 记住我cookie生效时间30天 ,单位秒;-->
        simpleCookie.setMaxAge(259200);
        return simpleCookie;
    }

    /**
     * cookie管理对象;
     * rememberMeManager()方法是生成rememberMe管理器，而且要将这个rememberMe管理器设置到securityManager中
     * @return
     */
    @Bean
    public CookieRememberMeManager rememberMeManager(){
        //System.out.println("ShiroConfiguration.rememberMeManager()");
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookie());
        //rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度(128 256 512 位)
        cookieRememberMeManager.setCipherKey(Base64.decode("2AvVhdsgUs0FSA3SDFAdag=="));
        return cookieRememberMeManager;
    }

//    @Bean
//    public DefaultWebSessionManager defaultWebSessionManager() {
//        return new DefaultWebSessionManager();
//    }

    @Bean
    public MyReaml myReaml() {
        return new MyReaml();
    }

//    /**
//     * 自定义的表单认证，主要是添加验证码
//     *Springboot不能用@Bean必须自己new，不然其他的匿名访问都无效了
//     * @return
//     */
//    @Bean
//    public MyFormAuthenticationFilter myFormAuthenticationFilter() {
//        MyFormAuthenticationFilter myFormAuthenticationFilter = new MyFormAuthenticationFilter();
//        //这里就是可以设置请求参数的名称。。。
////        myFormAuthenticationFilter.setUsernameParam("usernameaaa");
//        return myFormAuthenticationFilter;
//    }


    //加入注解的使用，不加入这个注解不生效
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    //加入注解的使用，不加入这个注解不生效
    @Bean
    @DependsOn({"lifecycleBeanPostProcessor"})
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    //加入注解的使用，不加入这个注解不生效
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }


    /**
     * anon	org.apache.shiro.web.filter.authc.AnonymousFilter
     * authc	org.apache.shiro.web.filter.authc.FormAuthenticationFilter
     * authcBasic	org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter
     * perms	org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter
     * port	org.apache.shiro.web.filter.authz.PortFilter
     * rest	org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter
     * roles	org.apache.shiro.web.filter.authz.RolesAuthorizationFilter
     * ssl	org.apache.shiro.web.filter.authz.SslFilter
     * user	org.apache.shiro.web.filter.authc.UserFilter
     * logout	org.apache.shiro.web.filter.authc.LogoutFilter
     */
/**
 * anon:例子/admins/**=anon 没有参数，表示可以匿名使用。
 * authc:例如/admins/user/**=authc表示需要认证(登录)才能使用，没有参数
 * roles：例子/admins/user/**=roles[admin],参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，当有多个参数时，例如admins/user/**=roles["admin,guest"],每个参数通过才算通过，相当于hasAllRoles()方法。
 * perms：例子/admins/user/**=perms[user:add:*],参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，例如/admins/user/**=perms["user:add:*,user:modify:*"]，当有多个参数时必须每个参数都通过才通过，想当于isPermitedAll()方法。
 * rest：例子/admins/user/**=rest[user],根据请求的方法，相当于/admins/user/**=perms[user:method] ,其中method为post，get，delete等。
 * port：例子/admins/user/**=port[8081],当请求的url的端口不是8081是跳转到schemal://serverName:8081?queryString,其中schmal是协议http或https等，serverName是你访问的host,8081是url配置里port的端口，queryString
 * 是你访问的url里的？后面的参数。
 * authcBasic：例如/admins/user/**=authcBasic没有参数表示httpBasic认证
 *
 * ssl:例子/admins/user/**=ssl没有参数，表示安全的url请求，协议为https
 * user:例如/admins/user/**=user没有参数表示必须存在用户，当登入操作时不做检查
 * 注：
 * anon，authcBasic，auchc，user是认证过滤器，
 * perms，roles，ssl，rest，port是授权过滤器
 */

}
