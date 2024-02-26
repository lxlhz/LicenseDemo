package com.example.licensedemo.utils;

import com.sun.org.apache.xml.internal.security.utils.Base64;
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
     *
     * @param errorPath   错误日志位置
     * @param licensePath 授权码文件位置
     * @param pubPath     公钥位置
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

            // 获取授权比较时间
            long compareTime = CompareTimeUtil.getCompareTime();
            // 判断授权时间
            if (compareTime >= endTime || compareTime < startTime) {
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
            log.error(e.getMessage(), e);
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
