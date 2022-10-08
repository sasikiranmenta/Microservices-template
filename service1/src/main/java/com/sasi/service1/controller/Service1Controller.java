package com.sasi.service1.controller;

import com.sasi.service1.service.FeignService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Service1Controller {

    final FeignService feignService;

    @RequestMapping(method = RequestMethod.GET, value = "service1-hello")
    public String hello() {
        return "Hello world frm service1";
    }

    @RequestMapping(method = RequestMethod.GET, value = "service1-feign")
    public String helloFeign() {
        return feignService.getFromService2();
    }


}
