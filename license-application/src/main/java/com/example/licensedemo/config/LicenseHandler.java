package com.example.licensedemo.config;

import com.example.licensedemo.utils.LicenseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * @Author: LiHuaZhi
 * @Date: 2021/8/20 15:38
 * @Description:
 **/
@Component
@Slf4j
public class LicenseHandler {

    public static Boolean license = false;

    private static int FAIL_NUM = 0;
    private static final int FAIL_MAX_NUM = 10;

    @Value("${sys.license.log}")
    private String errorPath;

    @Value("${sys.license.pub}")
    private String pubPath;

    @Value("${sys.license.key}")
    private String licensePath;

    public boolean loadLicense() {
        // 10次请求出现授权失败，则不加载授权文件
        if (FAIL_NUM >= FAIL_MAX_NUM) {
            return false;
        }
        // 当授权验证为false时，进行重新验证
        if (!license) {
            Map<String, String> map = LicenseUtil.loadLicense(errorPath, licensePath, pubPath);
            if (map != null && map.size() > 0) {
                FAIL_NUM = 0;
                license = true;
            } else {
                FAIL_NUM++;
                license = false;
            }
        }
        return license;
    }

    /**
     * 定时任务，bean不初始化时不会执行
     */
    @Scheduled(cron = "0 0 0 * * ?")
    public void scheduled() {
        Map<String, String> map = LicenseUtil.loadLicense(errorPath, licensePath, pubPath);
        if (map != null && map.size() > 0) {
            FAIL_NUM = 0;
            license = true;
        } else {
            license = false;
        }
    }
}