package cn.baikunlong.shirodemo.shiro;

import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class MyFormAuthenticationFilter extends FormAuthenticationFilter {
    /**
     * 这个就是使用authc（需登陆）的过滤器，我们现在需要验证码，所以重新写验证方法，
     * 也就是在验证账户密码之前先验证验证码
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return super.onAccessDenied(request, response);
    }
    //处理方法详见https://segmentfault.com/q/1010000010747919
    //但是其实只要自己new就不会错，不能让springboot代理
//    @Bean
//    public FilterRegistrationBean registration(MyFormAuthenticationFilter filter) {
//        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
//        registration.setEnabled(false);
//        return registration;
//    }
}
