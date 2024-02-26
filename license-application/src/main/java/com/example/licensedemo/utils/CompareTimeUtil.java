package com.example.licensedemo.utils;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @Author: LiHuaZhi
 * @Date: 2022/9/11 16:42
 * @Description: 获取比较时间工具类
 **/
@Slf4j
public class CompareTimeUtil {

    /**
     * AES偏移量16位，安装规则固定即可
     */
    private final static String AES_IV = "A64BF30925883C04";

    /**
     * 设置为CBC加密
     */
    private final static String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static String COMPARE_TIME = null;

    /**
     * 获取比较时间
     *
     * @return
     */
    public static Long getCompareTime() throws ParseException {

        // 解密比较时间
        String applicationInfo = CipherUtil.getApplicationInfo();
        String licenseCode = DecodeUtil.encryptBySymmetry(applicationInfo, DecodeUtil.AES_KEY, DecodeUtil.AES, true);
        String key = licenseCode.replaceAll("\\s*", "").replaceAll("[^(A-Za-z)]", "");
        key = key.length() > 16 ? key.substring(0, 16) : generateKey(key);

        // 解码
        String decrypt = decryptBySymmetry(CompareTimeUtil.COMPARE_TIME, key);
        // ASCII码转为数字
        String[] splits = decrypt.split("-");
        StringBuilder sb = new StringBuilder();
        for (String s : splits) {
            sb.append((char) (Integer.parseInt(s)));
        }
        String date = sb.toString();
        // 转化为时间戳
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        return sdf.parse(date).getTime();
    }


    /**
     * 重新加载比较时间
     *
     * @param filePath
     * @param endTime
     */
    public static void reLoadCompareTime(String filePath, long endTime) {
        try {
            // 截取原有比较时间
            long compareTime = CompareTimeUtil.getCompareTime();
            // 追加最新比较时间，增加一小时时间
            compareTime = compareTime + 60 * 60 * 1000;
            compareTime = Math.min(compareTime, endTime);

            // 设置新的比较时间
            String applicationInfo = CipherUtil.getApplicationInfo();
            String licenseCode = DecodeUtil.encryptBySymmetry(applicationInfo, DecodeUtil.AES_KEY, DecodeUtil.AES, true);
            String newCompareTime = generateCompareTime(compareTime, licenseCode);

            // 截取公钥部分
            PublicKey publicKey = DecodeUtil.loadPublicKeyFromFile(filePath);
            String keyString = Base64.encode(publicKey.getEncoded());

            // 写回文件
            keyString = keyString.concat("&").concat(newCompareTime);
            FileUtils.writeStringToFile(new File(filePath), keyString, String.valueOf(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        } finally {
            // 重置
            CompareTimeUtil.COMPARE_TIME = null;
        }
    }

    /**
     * 构建加密比较时间
     *
     * @param startTime   授权开始时间
     * @param licenseCode 授权机器码
     * @return
     */
    public static String generateCompareTime(Long startTime, String licenseCode) {

        Date date = new Date(startTime);
        DateFormat bf = new SimpleDateFormat("yyyyMMddHHmmss");
        String compareTime = bf.format(date);
        // 将字符转为ASCII码
        // 遍历字符串
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < compareTime.length(); i++) {
            sb.append((compareTime.charAt(i) - 0));
            if (i < compareTime.length() - 1) {
                sb.append("-");
            }
        }

        // 获取AES加密key,当前应用方的机器码的前16个字母，如果字母不管则使用`0`补充
        String key = licenseCode.replaceAll("\\s*", "").replaceAll("[^(A-Za-z)]", "");
        key = key.length() > 16 ? key.substring(0, 16) : generateKey(key);
        // 进行AES加密
        return encryptBySymmetry(sb.toString(), key);
    }

    private static String generateKey(String key) {
        for (int i = key.length(); i < 16; i++) {
            key = key.concat("0");
        }
        return key;
    }

    /**
     * 对称解密
     *
     * @param input : 密文
     * @param key   : 密钥
     * @throws Exception
     * @return: 原文
     */
    public static String decryptBySymmetry(String input, String key) {
        try {
            // 1,获取Cipher对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            // 指定密钥规则
            SecretKeySpec sks = new SecretKeySpec(key.getBytes(), "AES");
            // 默认采用ECB加密：同样的原文生成同样的密文
            // CBC加密：同样的原文生成的密文不一样

            // 使用CBC模式
            IvParameterSpec iv = new IvParameterSpec(AES_IV.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, sks, iv);

            // 3. 解密，上面使用的base64编码，下面直接用密文
            byte[] bytes = cipher.doFinal(Base64.decode(input));
            //  因为是明文，所以直接返回
            return new String(bytes);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("解密失败！");
        }
    }

    /**
     * 对称加密数据
     *
     * @param input : 原文
     * @param key   : 密钥
     * @return : 密文
     * @throws Exception
     */
    public static String encryptBySymmetry(String input, String key) {
        try {
            // 获取加密对象
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            // 创建加密规则
            // 第一个参数key的字节
            // 第二个参数表示加密算法
            SecretKeySpec sks = new SecretKeySpec(key.getBytes(), "AES");

            // ENCRYPT_MODE：加密模式
            // DECRYPT_MODE: 解密模式
            // 初始化加密模式和算法
            // 默认采用ECB加密：同样的原文生成同样的密文,并行进行
            // CBC加密：同样的原文生成的密文不一样,串行进行
            // 使用CBC模式
            IvParameterSpec iv = new IvParameterSpec(AES_IV.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, sks, iv);


            // 加密
            byte[] bytes = cipher.doFinal(input.getBytes());

            // 输出加密后的数据
            return Base64.encode(bytes);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("加密失败！");
        }
    }
}
