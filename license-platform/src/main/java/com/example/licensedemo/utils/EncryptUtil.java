package com.example.licensedemo.utils;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * @Author: LiHuaZhi
 * @Description: 加密工具类
 **/
public class EncryptUtil {

    public final static String RSA = "RSA";

    /**
     * 打印密钥对并且保存到文件
     * pubPath 公钥生成目录
     * priPath 私钥生成目录
     *
     * @return
     */
    public static void generateKeyPair(Long startTime, String licenseCode, String pubPath, String priPath) {
        try {
            //  创建密钥对生成器对象
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            // 生成密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            String privateKeyString = Base64.encode(privateKey.getEncoded());
            String publicKeyString = Base64.encode(publicKey.getEncoded());

            System.out.println("私钥：" + privateKeyString);
            System.out.println("公钥：" + publicKeyString);

            // 保存文件
            if (pubPath != null) {
                // 在公钥文件中追加一个当前时间戳，使用改时间与授权结束时间进行比较
                // 并且授权方会定时更新一个最新的时间，到公钥文件中
                // 获取比较时间
                String compareTime = CompareTimeUtil.generateCompareTime(startTime, licenseCode);
                publicKeyString = publicKeyString.concat("&").concat(compareTime);

                FileUtils.writeStringToFile(new File(pubPath), publicKeyString, String.valueOf(StandardCharsets.UTF_8));
            }
            if (priPath != null) {
                FileUtils.writeStringToFile(new File(priPath), privateKeyString, String.valueOf(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("生成密钥对失败！");
        }
    }

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
     * 从文件中加载私钥
     *
     * @param filePath : 文件路径
     * @return : 私钥
     * @throws Exception
     */
    public static PrivateKey loadPrivateKeyFromFile(String filePath) {
        try {
            // 将文件内容转为字符串
            String keyString = FileUtils.readFileToString(new File(filePath), String.valueOf(StandardCharsets.UTF_8));
            return loadPrivateKeyFromString(keyString);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("获取私钥文件字符串失败！");
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
     * 从字符串中加载私钥
     *
     * @param keyString : 私钥
     * @return : 私钥
     * @throws Exception
     */
    public static PrivateKey loadPrivateKeyFromString(String keyString) {
        try {
            // 进行Base64解码
            byte[] decode = Base64.decode(keyString);
            // 获取密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            // 构建密钥规范
            PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(decode);
            // 生成私钥
            return keyFactory.generatePrivate(key);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("获取私钥失败！");
        }
    }


    /**
     * 非对称加密数据
     *
     * @param input : 原文
     * @param key   : 密钥
     * @return : 密文
     * @throws Exception
     */
    public static String encryptByAsymmetric(String input, Key key) {
        try {
            // 获取Cipher对象
            Cipher cipher = Cipher.getInstance(RSA);
            // 初始化模式(加密)和密钥
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] resultBytes = getMaxResultEncrypt(input, cipher);
            return Base64.encode(resultBytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("加密失败！");
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
     * 分段处理加密数据
     *
     * @param input  : 加密文本
     * @param cipher : Cipher对象
     * @return
     */
    private static byte[] getMaxResultEncrypt(String input, Cipher cipher) throws Exception {
        byte[] inputArray = input.getBytes();
        int inputLength = inputArray.length;
        // 最大加密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 117;
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
     * 使用凯撒加密方式加密数据
     *
     * @param original :原文
     * @param key      :位移数量
     * @return :加密后的数据
     */
    public static String encryptKaiser(String original, int key) {
        // 将字符串转为字符数组
        char[] chars = original.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char aChar : chars) {
            // 获取字符的ascii编码
            int asciiCode = aChar;
            // 偏移数据
            asciiCode += key;
            // 将偏移后的数据转为字符
            char result = (char) asciiCode;
            // 拼接数据
            sb.append(result);
        }
        return sb.toString();
    }
}
