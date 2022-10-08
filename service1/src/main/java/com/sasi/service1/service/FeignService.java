package com.sasi.service1.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


@FeignClient(name = "service-2")
public interface FeignService {

    @RequestMapping(method = RequestMethod.GET, value = "/sasi/service2/webapp/service2-hello")
    public String getFromService2();

}
