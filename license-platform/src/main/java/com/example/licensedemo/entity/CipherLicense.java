package com.example.licensedemo.entity;

import com.sun.istack.internal.NotNull;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * @Author: LiHuaZhi
 * @Date: 2022/3/10 11:15
 * @Description:
 **/
@Data
public class CipherLicense {

    @ApiModelProperty(value = "开始时间(时间戳)", required = true)
    private Long startTime;


    @ApiModelProperty(value = "结束时间(时间戳)", required = true)
    private Long endTime;

    @ApiModelProperty(value = "授权码信息", required = true)
    private String licenseCode;
}
