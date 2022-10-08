package com.sasi.service2.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Service2Controller {

    @RequestMapping(method = RequestMethod.GET, value = "/service2-hello")
    public String hello() {
        return "Hello World from Service2";
    }
}
