package com.example.licensedemo.utils;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * @Author: LiHuaZhi
 * @Description: 解密工具类
 **/
public class DecodeUtil {

    public final static String RSA = "RSA";

    private final static String DES = "DES";

    public final static String AES = "AES";

    /**
     * AES加密算法，key的大小必须是16个字节，可以任意，必须与平台管理端保持一致
     */
    public final static String AES_KEY = "5LiN6KaB56C06Kej";

    /**
     * 设置为CBC加密，默认情况下ECB比CBC更高效
     */
    private final static String CBC = "/CBC/PKCS5Padding";


    /**
     * 从文件中加载公钥
     *
     * @param filePath : 文件路径
     * @return : 公钥
     * @throws Exception
     */
    public static PublicKey loadPublicKeyFromFile(String filePath) {
        try {
            // 将文件内容转为字符串
            String keyString = FileUtils.readFileToString(new File(filePath), String.valueOf(StandardCharsets.UTF_8));

            return loadPublicKeyFromString(keyString);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("获取公钥文件字符串失败！");
        }
    }

    /**
     * 从字符串中加载公钥
     *
     * @param keyString : 公钥
     * @return : 公钥
     * @throws Exception
     */
    public static PublicKey loadPublicKeyFromString(String keyString) {
        try {
            // 进行Base64解码
            byte[] decode = Base64.decode(keyString);
            // 获取密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            // 构建密钥规范
            X509EncodedKeySpec key = new X509EncodedKeySpec(decode);
            // 获取公钥
            return keyFactory.generatePublic(key);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("获取公钥失败！");
        }
    }

    /**
     * 非对称解密数据
     *
     * @param encrypted : 密文
     * @param key       : 密钥
     * @return : 原文
     * @throws Exception
     */
    public static String decryptByAsymmetric(String encrypted, Key key) {
        try {
            // 获取Cipher对象
            Cipher cipher = Cipher.getInstance(RSA);
            // 初始化模式(解密)和密钥
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(getMaxResultDecrypt(encrypted, cipher));
        } catch (
                Exception e) {
            e.printStackTrace();
            throw new RuntimeException("解密失败！");
        }
    }


    /**
     * 分段处理解密数据
     *
     * @param decryptText : 加密文本
     * @param cipher      : Cipher对象
     * @throws Exception
     */
    private static byte[] getMaxResultDecrypt(String decryptText, Cipher cipher) throws Exception {
        byte[] inputArray = Base64.decode(decryptText.getBytes(StandardCharsets.UTF_8));
        int inputLength = inputArray.length;

        // 最大解密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 128;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache = {};
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return resultBytes;
    }


    /**
     * 使用凯撒加密方式解密数据
     *
     * @param encryptedData :密文
     * @param key           :位移数量
     * @return : 源数据
     */
    public static String decryptKaiser(String encryptedData, int key) {
        // 将字符串转为字符数组
        char[] chars = encryptedData.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char aChar : chars) {
            // 获取字符的ASCII编码
            int asciiCode = aChar;
            // 偏移数据
            asciiCode -= key;
            // 将偏移后的数据转为字符
            char result = (char) asciiCode;
            // 拼接数据
            sb.append(result);
        }
        return sb.toString();
    }

    /**
     * 对称加密
     *
     * @param input     : 密文
     * @param key       : 密钥
     * @param algorithm : 类型：DES、AES
     * @return
     */
    public static String encryptBySymmetry(String input, String key, String algorithm) {
        return encryptBySymmetry(input, key, algorithm, false);
    }

    /**
     * 对称加密数据
     *
     * @param input     : 原文
     * @param key       : 密钥
     * @param algorithm : 类型：DES、AES
     * @param cbc       : CBC加密模式：同样的原文生成的密文不一样,串行进行，加密使用CBC解密也需要CBC
     * @return : 密文
     * @throws Exception
     */
    public static String encryptBySymmetry(String input, String key, String algorithm, Boolean cbc) {
        try {
            // 根据加密类型判断key字节数
            checkAlgorithmAndKey(key, algorithm);

            // CBC模式
            String transformation = cbc ? algorithm + CBC : algorithm;
            // 获取加密对象
            Cipher cipher = Cipher.getInstance(transformation);
            // 创建加密规则
            // 第一个参数key的字节
            // 第二个参数表示加密算法
            SecretKeySpec sks = new SecretKeySpec(key.getBytes(), algorithm);

            // ENCRYPT_MODE：加密模式
            // DECRYPT_MODE: 解密模式
            // 初始化加密模式和算法
            // 默认采用ECB加密：同样的原文生成同样的密文,并行进行
            // CBC加密：同样的原文生成的密文不一样,串行进行
            if (cbc) {
                // 使用CBC模式
                IvParameterSpec iv = new IvParameterSpec(key.getBytes());
                cipher.init(Cipher.ENCRYPT_MODE, sks, iv);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, sks);
            }

            // 加密
            byte[] bytes = cipher.doFinal(input.getBytes());

            // 输出加密后的数据
            return Base64.encode(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("加密失败！");
        }
    }

    /**
     * 对称解密
     *
     * @param input     : 密文
     * @param key       : 密钥
     * @param algorithm : 类型：DES、AES
     * @return
     */
    public static String decryptBySymmetry(String input, String key, String algorithm) {
        return decryptBySymmetry(input, key, algorithm, false);
    }

    /**
     * 对称解密
     *
     * @param input     : 密文
     * @param key       : 密钥
     * @param algorithm : 类型：DES、AES
     * @param cbc       : CBC加密模式：同样的原文生成的密文不一样,串行进行，加密使用CBC解密也需要CBC
     * @throws Exception
     * @return: 原文
     */
    public static String decryptBySymmetry(String input, String key, String algorithm, Boolean cbc) {
        try {
            // 根据加密类型判断key字节数
            checkAlgorithmAndKey(key, algorithm);

            // CBC模式
            String transformation = cbc ? algorithm + CBC : algorithm;

            // 1,获取Cipher对象
            Cipher cipher = Cipher.getInstance(transformation);
            // 指定密钥规则
            SecretKeySpec sks = new SecretKeySpec(key.getBytes(), algorithm);
            // 默认采用ECB加密：同样的原文生成同样的密文
            // CBC加密：同样的原文生成的密文不一样
            if (cbc) {
                // 使用CBC模式
                IvParameterSpec iv = new IvParameterSpec(key.getBytes());
                cipher.init(Cipher.DECRYPT_MODE, sks, iv);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, sks);
            }
            // 3. 解密，上面使用的base64编码，下面直接用密文
            byte[] bytes = cipher.doFinal(Base64.decode(input));
            //  因为是明文，所以直接返回
            return new String(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("解密失败！");
        }
    }

    private static void checkAlgorithmAndKey(String key, String algorithm) {
        // 根据加密类型判断key字节数
        int length = key.getBytes().length;
        boolean typeEnable = false;
        if (DES.equals(algorithm)) {
            typeEnable = length == 8;
        } else if (AES.equals(algorithm)) {
            typeEnable = length == 16;
        } else {
            throw new RuntimeException("加密类型不存在");
        }
        if (!typeEnable) {
            throw new RuntimeException("加密Key错误");
        }
    }
}
