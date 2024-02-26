package com.example.licensedemo.config;

import com.example.licensedemo.utils.CompareTimeUtil;
import com.example.licensedemo.utils.LicenseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

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
        // 当授权验证为false时，进行重新验证，让前十次验证时即使没有授权也能成功，直到连续失败十次
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
        return true;
    }

    /**
     * 定时任务，bean不初始化时不会执行，每隔一个小时执行一次
     */
//    @Scheduled(cron = "0/5 * * * * ?")
    @Scheduled(cron = "0 0 * * * ?")
    public void scheduled() {
        Map<String, String> map = LicenseUtil.loadLicense(errorPath, licensePath, pubPath);
        if (map != null && !CollectionUtils.isEmpty(map)) {
            FAIL_NUM = 0;
            license = true;

            long endTime = Long.parseLong(map.get("endTime"));
            // 将公钥文件中的 比较时间延长一小时，但是不能大于授权结束时间
            CompareTimeUtil.reLoadCompareTime(pubPath, endTime);
        } else {
            license = false;
        }
    }
}