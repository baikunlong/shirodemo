package cn.baikunlong.shirodemo.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class MyReaml extends AuthorizingRealm {
    public static String permission="adddd";//设置个变量，用来模拟数据库修改权限时用
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String primaryPrincipal = (String) principalCollection.getPrimaryPrincipal();

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRole("普通用户");
        simpleAuthorizationInfo.addStringPermission("select");
        simpleAuthorizationInfo.addStringPermission(permission);
        return simpleAuthorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = (String) authenticationToken.getPrincipal();
        if(!principal.equals("11")){
            throw new UnknownAccountException();
        }
        return new SimpleAuthenticationInfo(principal,"11",getName());
    }

    /**
     * 清除缓存，一般在权限更改后，service里调用的，现在测试在controller里
     */
    public void clearCached(){
        PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
        super.clearCache(principals);
    }
}
