package com.sasi.service2.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Service2Controller {

    @RequestMapping(method = RequestMethod.GET, value = "/service2-hello")
    public String hello() {
        return "Hello World from Service2";
    }

    @RequestMapping(method = RequestMethod.GET, value = "/protected")
    public String protectEndpoint() {
        return "Protected End point";
    }

    @Secured("ROLE_DELETE")
    @RequestMapping(method = RequestMethod.GET, value = "/delete")
    public String deleteEndpoint() {
        return "you are authorized for delete via method level security";
    }

    @PreAuthorize("hasAnyRole('EDIT', 'DELETE')")  //Authorization happens before executing a request
    @RequestMapping(method = RequestMethod.GET, value = "/edit")
    public String editEndpoint() {
        return "you are authorized for delete via method level PreAuthorize";
    }

    @PostAuthorize("hasAnyRole('USER', 'EDIT', 'DELETE')")
    //Authorization happens after executing all the functionalities
    @RequestMapping(method = RequestMethod.GET, value = "/getUser")
    public String getUsername(@AuthenticationPrincipal Jwt jwt) {
        return "Authorized via postAuthorized and your username is " + jwt.getClaims().get("sub");
    }


}
