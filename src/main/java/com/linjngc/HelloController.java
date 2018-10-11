package com.linjngc;

import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
public class HelloController {

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @RequestMapping("/hello")
    public String hello() {
       // User a =WebSecurityConfig.infoUser();

        return "hello";
    }


    /**
     * shiro 登录页 映射到路径 /login
     */
    @RequestMapping("/login")
    public String login(Model model) {
        User subject = (User)SecurityUtils.getSubject().getPrincipal();
        if(subject ==null){
            return "login";
        }else{
            model.addAttribute("user",subject);
            return "login";
        }
    }


    /**
     * 登录校验方法
     */
    @RequestMapping(value = "/loginUser",method = RequestMethod.POST)
    @ResponseBody
    public Object loginUser(String username,String password ,HttpServletRequest request) {
        UsernamePasswordToken usernamePasswordToken=new UsernamePasswordToken(username,password);
        Subject subject = SecurityUtils.getSubject();
        Map<String, Object> map = new HashMap<>();
        try {
            subject.login(usernamePasswordToken);   //完成登录
            User user1=(User) subject.getPrincipal();

            map.put("用户名称:", user1.getUsername());
            map.put("用户密码", user1.getPassword());
            return map;
        } catch(AccountException e) {
            map.put("登录失败信息1",e.getMessage());
            return map;//返回登录页面
        }
        catch(IncorrectCredentialsException e) {
            map.put("登录失败信息2","这下子真的是密码输出错误");
            return map;//返回登录页面
        }

    }




    @RequestMapping("/lo1")
    @ResponseBody
    public Object lo1() {
        User subject = (User)SecurityUtils.getSubject().getPrincipal();
        Map<String, Object> map = new HashMap<>();
        map.put("用户名",subject.getUsername());
        map.put("提示","你有add权限查看");
        return map;
    }


    @RequestMapping("/lo2")
    @ResponseBody
    public Object lo2() {
        User subject = (User)SecurityUtils.getSubject().getPrincipal();
        Map<String, Object> map = new HashMap<>();
        map.put("用户名",subject.getUsername());
        map.put("提示","你有update权限查看");
        return map;
    }

    @RequestMapping("/lo3")
    @ResponseBody
    public Object lo3() {
        User subject = (User)SecurityUtils.getSubject().getPrincipal();
        Map<String, Object> map = new HashMap<>();
        map.put("用户名",subject.getUsername());
        map.put("提示","你有delete权限查看");
        return map;
    }

    @RequestMapping("/lo4")
    @ResponseBody
    public Object lo4() {
        User subject = (User)SecurityUtils.getSubject().getPrincipal();
        Map<String, Object> map = new HashMap<>();
        map.put("用户名",subject.getUsername());
        map.put("提示","你有User权限查看");
        return map;
    }


    @RequestMapping("/lo5")
    @ResponseBody
    public Object lo5() {
        User subject = (User)SecurityUtils.getSubject().getPrincipal();
        Map<String, Object> map = new HashMap<>();
        map.put("用户名",subject.getUsername());
        map.put("提示","你有管理员这个角色查看");
        return map;
    }







    ///**
    // * 退出登录
    // */
    //@RequestMapping("/logout")
    //@ResponseBody
    //public String logOut(HttpSession session) {
    //    Subject subject = SecurityUtils.getSubject();
    //    subject.logout();
    //    return "注销成功";
    //}
}