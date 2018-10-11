package com.linjngc;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.ArrayList;
import java.util.List;


/**
 * shiro授权类
 */
public class AuthRealm extends AuthorizingRealm {
    //@Autowired
    //private UserService userService;
    
    //认证.登录
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken utoken=(UsernamePasswordToken) token;//获取用户输入的token
        String username = utoken.getUsername(); //
        System.out.println(" *****你输入的账号:"+utoken.getUsername());
        User user =new User();
        user.setUsername("ad");    //模拟查询
        user.setPassword("a123456");
        user.setId(999L);

        String salt="ABCDEFG";  //盐

        if (null == user) {
            throw new AccountException("帐号或密码不正确！");
        }
        return new SimpleAuthenticationInfo(user, user.getPassword(), ByteSource.Util.bytes(salt),getName());//放入shiro.调用CredentialsMatcher检验密码
    }
    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
        User token = (User) SecurityUtils.getSubject().getPrincipal();   //登录成功的用户
        SimpleAuthorizationInfo info =  new SimpleAuthorizationInfo();
        List<String> permissions=new ArrayList<>();  //权限

        // Set<Role> roles = user.getRoles();
        //if(roles.size()>0) {
        //    for(Role role : roles) {
        //        Set<Module> modules = role.getModules();
        //        if(modules.size()>0) {
        //            for(Module module : modules) {
        //                permissions.add(module.getMname());
        //            }
        //        }
        //    }
        //}
        permissions.add("add");//这里添加权限 可以添加多个权限
        permissions.add("update");
        permissions.add("delete");
        permissions.add("USER");



        List<String> roles=new ArrayList<>();  //角色
                    roles.add("管理员");


        info.addStringPermissions(permissions);//将权限放入shiro中.
        info.addRoles(roles);
        return info;
    }
}