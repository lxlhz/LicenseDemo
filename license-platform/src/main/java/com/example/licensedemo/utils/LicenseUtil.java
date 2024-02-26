package com.example.licensedemo.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: LiHuaZhi
 * @Description: 生成公钥私钥及授权码
 **/
@Slf4j
public class LicenseUtil {

    /**
     * 凯撒加密key
     */
    public final static Integer[] KAISER_KEY = {5, 11, 2, 19, 9, 12, 20, 8, 10};

    /**
     * 生成密钥对以及授权密文文件
     * 私钥加密，公钥解密
     * 加密时使用公钥加密，需要将生成的license.key和license.pub拷贝给用户，并且放到服务器的指定目录下
     * 私钥由平台管理员保存
     *
     * @param priPath     私钥文件地址 ,yml配置
     * @param licensePath 授权文件生成地址 ,yml配置
     * @param pubPath     公钥文件地址 ,yml配置
     * @param startTime   授权开始时间
     * @param endTime     授权开始时间
     * @param licenseCode 应用授权码，由用户通过接口根据一定规则生成
     * @return
     */
    public static void setLicense(String priPath, String licensePath, String pubPath, Long startTime, Long endTime, String licenseCode) {
        try {
            EncryptUtil.generateKeyPair(startTime, licenseCode, pubPath, priPath);

            // 生成随机key，只包含大写及数字
            String key = UUIDUtils.getUuId().toUpperCase();
            // 设置签名，key各字符的asc码，并且都为2位
            StringBuilder signBuilder = new StringBuilder();
            char[] chars = key.toCharArray();
            for (char c : chars) {
                String s = String.valueOf((int) c);
                if (s.length() != 2) {
                    throw new RuntimeException("生成的key格式错误");
                }
                signBuilder.append(s);
            }
            String sign = signBuilder.toString();

            // 生成参数
            StringBuilder paramBuilder = new StringBuilder();
            paramBuilder.append("key=").append(key).append("&startTime=").append(startTime)
                    .append("&endTime=").append(endTime)
                    .append("&sign=").append(sign)
                    .append("&licenseCode=").append(licenseCode);
            // 查看参数长度
            int length = paramBuilder.length();
            paramBuilder.append("&").append(length);
            String param = paramBuilder.toString();

            // 私钥加密参数
            // 从文件中加载私钥进行加密
            PrivateKey privateKey = EncryptUtil.loadPrivateKeyFromFile(priPath);
            // 公钥加密，私钥解密
            String encrypted = EncryptUtil.encryptByAsymmetric(param, privateKey);
            // 凯撒加密
            StringBuilder kaiserBuilder = new StringBuilder();
            char[] encryptedChars = encrypted.toCharArray();
            // 将私钥加密后密文的每个字符进行凯撒位移加密
            for (int index = 0; index < encryptedChars.length; index++) {
                int keyIndex = index % KAISER_KEY.length;
                char c = encryptedChars[index];
                String s = String.valueOf(c);
                String encryptKaiser = EncryptUtil.encryptKaiser(s, KAISER_KEY[keyIndex]);
                kaiserBuilder.append(encryptKaiser);
            }
            String encryptKaiser = kaiserBuilder.toString();

            // 将密文写入文件
            FileUtils.writeStringToFile(new File(licensePath), encryptKaiser, String.valueOf(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.error("生成授权文件失效！", e);
            throw new RuntimeException("生成授权文件失效!");
        }
    }


    /**
     * 自测授权文件与密钥是否正确
     * 加载授权密文文件进行校验
     * 私钥加密，公钥解密
     *
     * @param code        加密时用户的机器码
     * @param licensePath 授权文件位置
     * @param pubPath     公钥位置
     * @return
     */
    public static Map<String, String> testLicense(String code, String licensePath, String pubPath) {
        try {
            // 读取密文内容
            String licenseText = FileUtils.readFileToString(new File(licensePath), String.valueOf(StandardCharsets.UTF_8));
            // 凯撒解密
            StringBuilder kaiserBuilder = new StringBuilder();
            char[] decryptChars = licenseText.toCharArray();
            for (int index = 0; index < decryptChars.length; index++) {
                int keyIndex = index % KAISER_KEY.length;
                char c = decryptChars[index];
                String s = String.valueOf(c);
                String encryptKaiser = EncryptUtil.decryptKaiser(s, KAISER_KEY[keyIndex]);
                kaiserBuilder.append(encryptKaiser);
            }
            String decryptLicense = kaiserBuilder.toString();
            // 使用私密进行解密获取加密参数
            // 从文件中加载公钥
            PublicKey publicKey = EncryptUtil.loadPublicKeyFromFile(pubPath);
            // 获取原文参数
            String params = EncryptUtil.decryptByAsymmetric(decryptLicense, publicKey);

            // 验证参数的长度
            int length = Integer.parseInt(params.substring(params.lastIndexOf("&") + 1));
            String param = params.substring(0, params.lastIndexOf("&"));
            if (param.length() != length) {
                throw new RuntimeException("验证参数长度校验失败!");
            }
            Map<String, String> paramMap = getParamMap(param);
            String key = paramMap.get("key");
            String sign = paramMap.get("sign");
            long startTime = Long.parseLong(paramMap.get("startTime"));
            long endTime = Long.parseLong(paramMap.get("endTime"));
            String licenseCode = paramMap.get("licenseCode");

            // 将key再次转为sign，验证key的签名是否正确
            StringBuilder signBuilder = new StringBuilder();
            char[] chars = key.toCharArray();
            for (char c : chars) {
                String s = String.valueOf((int) c);
                if (s.length() != 2) {
                    throw new RuntimeException("生成的key格式错误");
                }
                signBuilder.append(s);
            }
            String signKey = signBuilder.toString();
            if (!signKey.equals(sign)) {
                throw new RuntimeException("解析key的签名错误");
            }

            // 判断授权时间
            long now = System.currentTimeMillis();
            if (now >= endTime || now < startTime) {
                throw new RuntimeException("授权时间无效!");
            }

            // 验证授权码是否正确
            // 对解析授权码与传入的授权码进行对比
            if (!licenseCode.equals(code)) {
                throw new RuntimeException("授权码不匹配!");
            }

            System.out.println("授权验证成功！");
            return paramMap;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private static Map<String, String> getParamMap(String param) {
        Map<String, String> map = new HashMap<>(8);
        // param为：key=1111&startTime=123.....
        String[] split = param.split("&");
        for (String s : split) {
            // 找到第一个"="位置，然后进行分割
            int indexOf = s.indexOf("=");
            String key = s.substring(0, indexOf);
            String value = s.substring(indexOf + 1);
            map.put(key, value);
        }
        return map;
    }

}
