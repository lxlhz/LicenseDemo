package com.example.licensedemo.controller;

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
