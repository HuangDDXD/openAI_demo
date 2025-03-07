package com.dd.chatgpt.domain.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

/**
 * JWT工具类
 */
@Data
public class JwtUtil {

    /**
     * 默认算法
     */
    private static final SignatureAlgorithm defaultSignatureAlgorithm = SignatureAlgorithm.HS256;
    // 有效期为
    public static final Long JWT_TTL = 60 * 60 * 1000L;// 60 * 60 *1000  一个小时
    // 设置秘钥明文  默认密钥
    public static final String JWT_KEY = "singing";
    // 签发者
    public static final String JWT_ISSUER = "zy";

    // 算法
    private SignatureAlgorithm signatureAlgorithm;

    public JwtUtil(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * 获取uuid
     *
     * @return 唯一标识
     */
    public static String getUUID() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    /**
     * 生成加密后的秘钥 secretKey
     *
     * @return secretKey
     */
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    /**
     * 获取jwt构造器
     *
     * @param subject   主题
     * @param ttlMillis 过期时间
     * @param uuid      uuid
     * @return JwtBuilder
     */
    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid, Map<String, Object> chaim) {
        SecretKey secretKey = generalKey();
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        if (ttlMillis == null) {
            ttlMillis = JwtUtil.JWT_TTL;
        }
        if (Objects.isNull(chaim)) {
            chaim = new HashMap<>();
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .setClaims(chaim)
                // 唯一的ID
                .setId(uuid)
                // 主题  可以是JSON数据
                .setSubject(subject)
                // 签发者
                .setIssuer(JwtUtil.JWT_ISSUER)
                // 签发时间
                .setIssuedAt(now)
                // 使用HS256对称加密算法签名, 第二个参数为秘钥
                .signWith(defaultSignatureAlgorithm, secretKey)
                .setExpiration(expDate);
    }

    /**
     * 生成jtw  无过期时间
     *
     * @param subject token中要存放的数据（json格式）
     * @return jwtStr
     */
    public static String createJWT(String subject) {
        // 无过期时间
        JwtBuilder builder = getJwtBuilder(subject, null, getUUID(),null);
        return builder.compact();
    }

    /**
     * 生成jtw  指定过期时间、指定载荷
     *
     * @param subject   token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return jwtStr
     */
    public static String createJWT(String subject, Long ttlMillis, Map<String, Object> chaim) {
        // 设置过期时间
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID(),chaim);
        return builder.compact();
    }


    /**
     * 创建token  指定过期时间、id(唯一标识)
     *
     * @param id        唯一标识
     * @param subject   主题
     * @param ttlMillis 过期时间
     * @return jwtStr
     */
    public static String createJWT(String subject, Long ttlMillis, String id) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id,null);
        return builder.compact();
    }

    /**
     * 创建token  指定过期时间、id(唯一标识)、指定载荷
     *
     * @param id        唯一标识
     * @param subject   主题
     * @param ttlMillis 过期时间
     * @return jwtStr
     */
    public static String createJWT(String subject, Long ttlMillis, String id, Map<String, Object> chaim) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id, chaim);
        return builder.compact();
    }

    /**
     * 解析
     *
     * @param jwt 字符串
     * @return Claims
     * @throws Exception 异常
     */
    public static Claims parseJWT(String jwt) throws Exception {
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }

    // 判断jwtToken是否合法
    public static boolean isVerify(String jwtToken) {
        // 这个是官方的校验规则，这里只写了一个”校验算法“，可以自己加
        Algorithm algorithm = null;
        switch (JwtUtil.defaultSignatureAlgorithm) {
            case HS256:
                algorithm = Algorithm.HMAC256(JwtUtil.JWT_KEY);
                break;
            default:
                throw new RuntimeException("不支持该算法");
        }
        JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(jwtToken);
        // 校验不通过会抛出异常
        // 判断合法的标准：1. 头部和荷载部分没有篡改过。2. 没有过期
        return true;
    }

    // 测试
    public static void main(String[] args) throws Exception {
        String jwt = createJWT("123");
        System.out.println(jwt);
        Claims claims = parseJWT(jwt);
        System.out.println(claims);
    }


}