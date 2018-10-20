package cn.baikunlong.shirodemo.controller;

import cn.baikunlong.shirodemo.shiro.MyReaml;
import cn.baikunlong.shirodemo.utils.Captcha;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.IOException;

@Controller
public class MyController {
    //注入MyReaml用来清除缓存
    @Autowired
    private MyReaml myReaml;
//    @Autowired
//    private DefaultWebSessionManager defaultWebSessionManager;

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    @ResponseBody
    public String login(String username, String password,boolean rememberMe,HttpServletRequest httpServletRequest) {
        //获取到验证码
        String customCaptcha = httpServletRequest.getParameter("captcha");
        String realCaptcha = (String) httpServletRequest.getSession().getAttribute("captcha");
        System.out.println("session里取出来的验证码："+realCaptcha+",用户输入："+customCaptcha);
        if(realCaptcha!=null&&customCaptcha!=null&&!realCaptcha.equalsIgnoreCase(customCaptcha)){
            System.out.println("验证码异常1");
            return "验证码错误";
        } else if(customCaptcha==null&&realCaptcha!=null){//如果直接访问接口不传验证码
            System.out.println("验证码异常2");
            return "验证码错误";
        } else if(realCaptcha==null){
            System.out.println("验证码异常3");
            return "验证码错误";
        }
        UsernamePasswordToken token = new UsernamePasswordToken(username, password,rememberMe);
        try {
            Subject subject = SecurityUtils.getSubject();
            subject.login(token);
            boolean authenticated = subject.isAuthenticated();//是否认证过
            if (authenticated){
                System.out.println("认证通过了");
            }else {
                System.out.println("认证没有通过");
            }
        }catch (UnknownAccountException e) {
            e.printStackTrace();
            return "用户不存在";
        } catch (IncorrectCredentialsException e) {
            e.printStackTrace();
            return "密码错误";
        } catch (Exception e) {
            e.printStackTrace();
            return "未知错误";
        }
        return "登陆成功";
    }

    @RequestMapping(value = "/add", method = RequestMethod.GET)
    @RequiresPermissions("add")
    @ResponseBody
    public String add() {
        return "添加成功";
    }

    @RequestMapping(value = "/updatePerms", method = RequestMethod.GET)
    @ResponseBody
    public String updatePerms() {
        MyReaml.permission="add";//修改权限为add（这样就可以访问add接口了）
        myReaml.clearCached();//清除权限缓存
        return "修改权限成功";
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public void logout(HttpServletResponse response,HttpServletRequest request) {
        //加入session管理后注销时会异常，不知为何，先抓住（抓不住。。。）
        //经过一晚上也没有找到解决方法。先放下了。。。
        String id = request.getSession().getId();
        try {
//            myReaml.clearCached();
            SecurityUtils.getSubject().logout();
        } catch (Exception e) {
            System.out.println("用户名为：" + (String) SecurityUtils.getSubject().getPrincipal() + "，注销抛异常了");
            e.printStackTrace();
        }
        System.out.println("注销成功");
//        return "login.html";
    }
//    @RequestMapping("/getActiveUsers")
//    @ResponseBody
//    public String getActiveUsers(){
//        Collection<Session> activeSessions = defaultWebSessionManager.getSessionDAO().getActiveSessions();
//        int size = activeSessions.size();
//        return "当前在线人数："+size;
//    }

    @RequestMapping("/getCaptcha")
    public void getCaptcha(HttpServletRequest request, HttpServletResponse response){
        Captcha captcha = new Captcha();
        BufferedImage image = captcha.getImage();//获取一次性验证码图片
        try {
            Captcha.output(image, response.getOutputStream());//把图片写到指定流中
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 把文本保存到session中,在MyFormAuthenticationFilter中需要验证
        String text = captcha.getText();
        System.out.println("真实验证码："+text);
        try {
            //这里在注销后回到login界面时，会不能创建session
            //Cannot create a session after the response has been committed
            //也就是这里出现的有时候session里验证码为空的情况
            request.getSession().setAttribute("captcha", text);
        } catch (Exception e) {
            e.printStackTrace();
        }
//        System.out.println(request.getSession().getAttribute("captcha"));
//        System.out.println("真实验证码："+captcha.getText());
    }

}