package com.example.licensedemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2WebMvc;



/**
 * @author LiGezZ
 */
@Configuration
@EnableSwagger2WebMvc
public class SwaggerConfiguration {

    @Bean("system-service")
    public Docket groupRestApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(groupApiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.example.licensedemo.controller"))
                .paths(PathSelectors.any())

                .build();
    }

    private ApiInfo groupApiInfo() {
        return new ApiInfoBuilder()
                .title("license-platform")
                .description("管理平台")
                .termsOfServiceUrl("")
                .version("1.0")
                .build();
    }

}