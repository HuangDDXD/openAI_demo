package com.dd.chatgpt.domain.security.service;

import com.dd.chatgpt.domain.security.model.vo.LoginUser;
import com.dd.chatgpt.domain.security.model.vo.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * @Author zy
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 根据用户名查询用户信息
        // LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        // wrapper.eq(User::getUserName,username);
        // User user = userMapper.selectOne(wrapper);
        // 如果查询不到数据就通过抛出异常来给出提示
        User user = new User();
        user.setId(123L);
        user.setUserName("jojo");
        user.setPassword(new BCryptPasswordEncoder().encode("123"));
        if(Objects.isNull(username)){
            throw new RuntimeException("用户名或密码错误");
        }
        // TODO 根据用户查询权限信息 添加到LoginUser中
        // 封装成UserDetails对象返回
        //往后走，security内部逻辑在做秘密验证
        return new LoginUser(user);
    }
}