package com.dd.chatgpt.interfaces;

import com.dd.chatgpt.Application;
import com.dd.chatgpt.domain.security.model.vo.User;
import com.dd.chatgpt.domain.security.service.LoginServiceImpl;
import com.dd.chatgpt.domain.security.utils.ResponseResult;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jojo3
 * @date 2025/3/6 17:51
 * @description API访问准入管理：当访问OpenAI 接口时，需要进行准入验证
 */
@RestController
public class ApiAccessController {

    private final Logger logger = LoggerFactory.getLogger(ApiAccessController.class);

    @Resource
    private LoginServiceImpl loginService;

    /**
     * http://localhost:8080/authorize?username=jojo&password=123
     */
    @RequestMapping("/authorize")
    public ResponseResult<?> authorize(String username, String password) {
        Map<String, String> map = new HashMap<>();
        // 模拟账号和密码校验
        if (!"jojo".equals(username) || !"123".equals(password)) {
            map.put("msg", "用户名密码错误");
            return new ResponseResult<>(403,"登陆失败",map);
        }
        User user = new User();
        user.setUserName(username);
        user.setPassword(password);
        ResponseResult<?> result = loginService.login(user);
        // 校验通过生成token
        // Map<String, Object> chaim = new HashMap<>();
        // chaim.put("username", username);
        // String jwtToken = JwtUtil.createJWT(username, 5 * 60 * 1000L, chaim);
        // 返回token码
        return result;
    }

    /**
     * http://localhost/api/verify?token=
     */
    @RequestMapping("/verify")
    public ResponseEntity<String> verify(String token) {
        logger.info("验证 token：{}", token);
        return ResponseEntity.status(HttpStatus.OK).body("verify success!");
    }

    @RequestMapping("/success")
    public String success(){
        return "test success by jojo";
    }

}

