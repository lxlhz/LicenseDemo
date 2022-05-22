@[TOC](目录)
离线授权可以让应用系统在不请求外部网络的情况下进行授权验证的手段；也就是说应用自身持有一把锁，该锁相当于一个门闸，访问应用时需要需要使用门禁卡；在开门时会验证门禁卡是否已经过期，是否为当前小区的卡；而这些验证操作都不会依赖于第三方应用，自身就可以完成；

# 1、说明
离线授权方案分为授权申请和授权验证两个过程，其中授权申请在授权有效期内，只会进行一次；授权验证会验证每天的第一个请求或者定时任务验证一次，流程如下图：

**离线授权申请流程：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/0483aaf4ec284428aa31b830eaebf2d8.png#pic_center)

**离线授权验证流程：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/34487a05d02b453e9f1da76b4af948b4.png#pic_center)

# 2、平台系统
**搭建系统：** `license-platform`
## 2.1 加密工具类
主要使用了凯撒加密、RSA非对称加密，在工具类中生成私钥和公钥，并且将时间、机器码等参数通过私钥加密形成加密文件，在应用系统中使用公钥进行解密，流程如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/0483aaf4ec284428aa31b830eaebf2d8.png#pic_center)
**代码实现 - `EncryptUtil`：**
```java

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
    public static void generateKeyPair(String pubPath, String priPath) {
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
```
## 2.2 授权工具类
将应用系统的机器码、授权日期、授权Key等参数通过`EncryptUtil`工具，把公钥、私钥、授权码以文件的形式输出到指定位置，再由平台管理员将公钥、授权吗发放给应用系统；

**代码实现 - `LicenseUtil`：**
```java

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
     * @param priPath 私钥文件地址 ,yml配置
     * @param licensePath 授权文件生成地址 ,yml配置
     * @param pubPath 公钥文件地址 ,yml配置
     * @param  startTime 授权开始时间
     * @param  endTime 授权开始时间
     * @param licenseCode 应用授权码，由用户通过接口根据一定规则生成
     * @return
     */
    public static void setLicense(String priPath, String licensePath, String pubPath,  Long startTime, Long endTime, String licenseCode) {
        try {
            EncryptUtil.generateKeyPair(pubPath, priPath);

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
            log.error("生成授权文件失效！");
            throw new RuntimeException("生成授权文件失效!");
        }
    }


    /**
     * 自测授权文件与密钥是否正确
     * 加载授权密文文件进行校验
     * 私钥加密，公钥解密
     * @param code 加密时用户的机器码
     * @param licensePath 授权文件位置
     * @param pubPath 公钥位置
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
            if (now > endTime || now < startTime) {
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
            e.printStackTrace();
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
```

## 2.3 properties配置
系统相关的配置
```json
server.port=9191
server.servlet.context-path=/license-platform
sys.license.key = C:\\Users\\lhz12\\Desktop\\test\\license.key
sys.license.pri = C:\\Users\\lhz12\\Desktop\\test\\license.pri
sys.license.pub = C:\\Users\\lhz12\\Desktop\\test\\license.pub
```
## 2.4 授权码Controller 
Controller作为入口类，根据传入的机器码、授权日期调用`LicenseUtil`，并且提供接口进行自测
```java
import com.example.licensedemo.entity.CipherLicense;
import com.example.licensedemo.utils.LicenseUtil;
import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * @Author: LiHuaZhi
 * @Description:
 **/
@Api(tags = "加密授权接口管理")
@RestController
@RequestMapping("/cipher")
@Slf4j
public class CipherController {
    @Value("${sys.license.key}")
    private String keyPath;

    @Value("${sys.license.pri}")
    private String priPath;

    @Value("${sys.license.pub}")
    private String pubPath;


    /**
     * 生成公钥和授权文件-内部接口,实际情况下这两个接口应该独立出来，不会在包里面
     *
     * @return
     */
    @ApiOperation(value = "生成公钥和授权文件", notes = "生成公钥和授权文件")
    @ApiOperationSupport(order = 5)
    @PostMapping("/set")
    public Object setLicense(@RequestBody CipherLicense param) {
        LicenseUtil.setLicense(priPath, keyPath, pubPath, param.getStartTime(), param.getEndTime(), param.getLicenseCode());
        return "操作成功";
    }

    /**
     * @return
     */
    @ApiOperation(value = "手动通过公钥和授权文件实现授权验证", notes = "手动通过公钥和授权文件实现授权验证")
    @ApiOperationSupport(order = 5)
    @GetMapping("/load")
    public Object loadLicense(String code) {
        Map<String, String> map = LicenseUtil.testLicense(code, keyPath, pubPath);
        System.out.println(map);
        if (map != null && map.size() > 0) {
            return "操作成功";
        } else {
            return "操作失败";
        }
    }
}
```

## 2.5 测试
通过`swagger`调用接口进行测试，地址：[http://localhost:9191/license-platform/doc.html](http://localhost:9191/license-platform/doc.html)

**第一步：生成授权码、公钥、私钥文件**
![在这里插入图片描述](https://img-blog.csdnimg.cn/4d461be5e1044bcd8061ac555d96cb26.png#pic_center)

**生成的公钥、私钥、授权码文件：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/381b2aa470bd4978beba5495e7c4dda6.png#pic_center)

**第二步：自测验证授权码是否正确**
该步骤为模拟应用系统的验证授权的一个过程，只有用到`公钥、授权码文件、机器码`,这些都是应该让应用系统拥有的，不能将`私钥`暴漏给应用系统；

![在这里插入图片描述](https://img-blog.csdnimg.cn/ff5040aff34848e7b25b76943ec1d216.png#pic_center)

**授权验证成功：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/6bb04c8b161e4f2e9cf967cfd33a0ac0.png#pic_center)

# 3、应用系统
**搭建系统：** `license-application`
![在这里插入图片描述](https://img-blog.csdnimg.cn/34487a05d02b453e9f1da76b4af948b4.png#pic_center)

## 3.1 解密工具类
主要使用了凯撒解密、RSA非对称解密，在工具类中利用公钥解析授权码文件，获取时间、机器码等参数；

**代码实现 - `DecodeUtil`：**
```java

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

```

## 3.2 授权工具类
将应用系统的机器码、授权日期、等参数与通过`DecodeUtil`工具类中利用公钥解析授权码文件，获取时间、机器码的参数进行比较，如果匹配则表示授权成功；

**代码实现 - `LicenseUtil`：**
```java

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

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

    public final static long MAX_ERROR_FILE = 10 * 1024 * 1024;
    public final static int MAX_ERROR_FILE_NUM = 10;
    public final static String ERROR_FILE_DEFAULT = "error.log";
    public final static String ERROR_FILE_PREFIX = "error-";
    public final static String ERROR_FILE_SUFFIX = ".log";


    /**
     * 加载授权码文件，判断是否授权成功
     * @param errorPath 错误日志位置
     * @param licensePath 授权码文件位置
     * @param pubPath 公钥位置
     * @return
     */
    public static Map<String, String> loadLicense(String errorPath, String licensePath, String pubPath) {
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
                String encryptKaiser = DecodeUtil.decryptKaiser(s, KAISER_KEY[keyIndex]);
                kaiserBuilder.append(encryptKaiser);
            }
            String decryptLicense = kaiserBuilder.toString();
            // 使用私密进行解密获取加密参数
            // 从文件中加载公钥
            PublicKey publicKey = DecodeUtil.loadPublicKeyFromFile(pubPath);
            // 获取原文参数
            String params = DecodeUtil.decryptByAsymmetric(decryptLicense, publicKey);

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
            if (now > endTime || now < startTime) {
                throw new RuntimeException("授权时间无效!");
            }

            // 验证授权码是否正确
            // 获取服务器的硬件信息编码
            String applicationInfo = CipherUtil.getApplicationInfo();
            // 对授权码进行解密
            String encryptData = DecodeUtil.decryptBySymmetry(licenseCode, DecodeUtil.AES_KEY, DecodeUtil.AES, true);

            // 对授权码进行与硬件信息编码进行匹配
            if (!applicationInfo.equals(encryptData)) {
                throw new RuntimeException("授权码不匹配!");
            }

            System.out.println("授权验证成功！");
            return paramMap;
        } catch (Exception e) {
            e.printStackTrace();
            try {
                writeErrorToFile(e, errorPath);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            return null;
        }
    }

    /**
     * 将授权的错误信息写入文件
     *
     * @param e
     * @param errorPath
     * @throws IOException
     */
    private static void writeErrorToFile(Exception e, String errorPath) throws IOException {
        File parentFile = new File(errorPath);
        // 获取当前文件夹，的所有文件列表
        File[] listFiles = parentFile.listFiles();
        int fileNum = 1;
        List<File> fileList = new ArrayList<>();
        if (listFiles != null) {
            // 按修改日期排行
            for (File sonFile : listFiles) {
                if (sonFile.getName().contains(ERROR_FILE_PREFIX)) {
                    fileNum++;
                    fileList.add(sonFile);
                }
            }
        }

        // 如果文件过大(10MB)，则先复制副本，再进行删除
        File file = new File(errorPath + File.separator + ERROR_FILE_DEFAULT);
        if (file.exists() && file.length() > MAX_ERROR_FILE) {
            // 按照日期排序
            List<File> fileCollect = fileList.stream().sorted(Comparator.comparing(File::lastModified)).collect(Collectors.toList());
            // 如果大于10个，则删除文件，只保留10个
            while (fileCollect.size() >= MAX_ERROR_FILE_NUM) {
                boolean delete = fileCollect.get(0).delete();
                fileCollect.remove(0);
            }
            for (int index = 0; index < fileCollect.size(); index++) {
                String name = errorPath + File.separator + ERROR_FILE_PREFIX + (index + 1) + ERROR_FILE_SUFFIX;
                boolean b = fileCollect.get(index).renameTo(new File(name));
            }
            fileNum = Math.min(fileNum, MAX_ERROR_FILE_NUM);
            String newErrorFile = errorPath + File.separator + ERROR_FILE_PREFIX + fileNum + ERROR_FILE_SUFFIX;
            // 重新命名
            boolean b = file.renameTo(new File(newErrorFile));
            // 删除原文件
            boolean delete = file.delete();
        }
        // 获取当前日期
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String format = dateTimeFormatter.format(now);
        String message = format + " " + e.getMessage() + "\n";
        FileUtils.writeStringToFile(file, message, String.valueOf(StandardCharsets.UTF_8), true);
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
```

## 3.3 properties配置
系统相关的配置
```json
server.port=9292
server.servlet.context-path=/license-application
sys.license.log = C:\\Users\\lhz12\\Desktop\\license
sys.license.key = C:\\Users\\lhz12\\Desktop\\license\\license.key
sys.license.pub = C:\\Users\\lhz12\\Desktop\\license\\license.pub
```
## 3.4 授权 Controller 
Controller作为入口类，根据传入的机器码、授权日期调用`LicenseUtil`，并且提供接口进行自测
```java
import com.example.licensedemo.utils.CipherUtil;
import com.example.licensedemo.utils.DecodeUtil;
import com.example.licensedemo.utils.LicenseUtil;
import com.github.xiaoymin.knife4j.annotations.ApiOperationSupport;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author: LiHuaZhi
 * @Description:
 **/
@Api(tags = "加密授权接口管理")
@RestController
@RequestMapping("/cipher")
@Slf4j
public class CipherController {
    @Value("${sys.license.key}")
    private String keyPath;

    @Value("${sys.license.log}")
    private String logPath;

    @Value("${sys.license.pub}")
    private String pubPath;


    /**
     * 用户在点击，查看`授权信息`按钮时，请求check接口,进行一次授权验证(每天第一次通过其他接口访问系统时，也会验证一次 )
     * 如果通过则返回授权信息(开始+结束时间)
     * 如果失败则返回授权码
     *
     * @return
     */
    @ApiOperation(value = "获取以及验证授权信息", notes = "获取以及验证授权信息")
    @ApiOperationSupport(order = 5)
    @GetMapping("/check")
    public Object check() {
        // 验证是否通过了授权，通过了返回授权信息(开始+结束时间)
        try {
            Map<String, String> map = LicenseUtil.loadLicense(logPath, keyPath, pubPath);
            if (map != null && map.size() > 0) {
                long startTime = Long.parseLong(map.get("startTime"));
                long endTime = Long.parseLong(map.get("endTime"));
                // 只返回授权开始和结束时间给页面
                Map<String, Long> resultMap = new HashMap<>(4);
                resultMap.put("startTime", startTime);
                resultMap.put("endTime", endTime);
                return resultMap;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        String applicationInfo = CipherUtil.getApplicationInfo();
        String encryptAes = DecodeUtil.encryptBySymmetry(applicationInfo, DecodeUtil.AES_KEY, DecodeUtil.AES, true);
        log.debug("授权码:" + encryptAes);
        return encryptAes;

    }
    @ApiOperation(value = "测试请求拦截验证", notes = "测试请求拦截验证")
    @ApiOperationSupport(order = 5)
    @GetMapping("/test")
    public String test() {
        return "请求成功";
    }

}

```
## 3.5 拦截器实现
在拦截器中，拦截除了`/cipher/check`以外的所有接口，在拦截器中需要判断应用是否授权成功；
```java
@Component
@Slf4j
public class LicenseInterceptor implements HandlerInterceptor {

    @Resource
    private LicenseHandler licenseHandler;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        log.debug("进入拦截器,URL:{}",request.getServletPath());

        // 查看是否授权成功
        boolean license = licenseHandler.loadLicense();
            if (!license) {
                throw new RemoteException("系统暂未授权");
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {

    }
}
```
## 3.6、测试
==将平台管理端与应用系统端都启动起来==

**1、访问应用系统的`/test`接口：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/b6f5bac6eb7a408a822f309f1bacda7d.png#pic_center)
**查看控制台：**
打印了错误信息，因为系统还没有开始授权
![在这里插入图片描述](https://img-blog.csdnimg.cn/8160d1bdce0543209df63be6ff62c15c.png#pic_center)
```
```

**2、访问应用系统的`/check`接口：**
再请求接口后，没有提示验证成功，而是返回了需要进行授权的`机器码`
![在这里插入图片描述](https://img-blog.csdnimg.cn/63f2bb4ecadc4b1ebca09d4bdc6d5d9d.png#pic_center)
```
```
**3、拷贝机器码，访问管理平台的`生成公钥和授权文件`接口：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/fac86cf3e8bb4130a01c6ea7290dc3d5.png#pic_center)
```
```
**4、拷贝公钥、授权码文件**
将管理平台的生成的公钥、授权码文件拷贝到`C:\Users\lhz12\Desktop\license`目录下，改目录为`应用系统的application.properties`配置的读取目录，此过程模拟实际场景中通过U盘等方式的拷贝情景；
![在这里插入图片描述](https://img-blog.csdnimg.cn/006a8e63587e4eee8c4ebeb15a847fa0.png)
**文件拷贝：**
![在这里插入图片描述](https://img-blog.csdnimg.cn/19fa9f6496204659bfb340cf20e4cc95.png)

**5、再次访问应用系统的`/test`接口：**

再次访问时，系统已经提示成功了
![在这里插入图片描述](https://img-blog.csdnimg.cn/6d3a853246384d81887b8d6f62b5d1ad.png#pic_center)

**6、再次访问应用系统的`/check`接口：**

check接口返回了，系统授权的开始与结束时间，表示授权成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/7a051026883f462e882ec85e90655716.png#pic_center)
