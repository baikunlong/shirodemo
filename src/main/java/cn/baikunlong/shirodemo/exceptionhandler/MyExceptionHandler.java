package cn.baikunlong.shirodemo.exceptionhandler;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.session.UnknownSessionException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@ControllerAdvice
public class MyExceptionHandler {
    /**
     * 登录认证异常
     */
//    @ExceptionHandler({ UnauthenticatedException.class, AuthenticationException.class })
//    public ModelAndView authenticationException(HttpServletRequest request, HttpServletResponse response) {
//
//    }

    /**
     * 权限异常
     */
    @ExceptionHandler({UnauthorizedException.class, AuthorizationException.class})
    public ModelAndView authorizationException(HttpServletRequest request, HttpServletResponse response) {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("403.html");
        System.out.println("用户名为：" + (String) SecurityUtils.getSubject().getPrincipal() +
                "，无权访问此url:" + request.getRequestURI());
        return modelAndView;
    }

}