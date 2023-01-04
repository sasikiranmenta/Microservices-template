package com.sasi.service1.controller;

import com.sasi.service1.service.FeignService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

@RestController
@RequiredArgsConstructor
public class Service1Controller {

    final FeignService feignService;
    final WebClient webClient;


    @PreAuthorize("hasAuthority('SCOPE_profile')")
    @RequestMapping(method = RequestMethod.GET, value = "service1-hello")
    public String hello() {
        return "Hello world frm service1";
    }

    @RequestMapping(method = RequestMethod.GET, value = "service1-feign")
    public String helloFeign() {
        return feignService.getFromService2();
    }

    @PostAuthorize("hasAuthority('SCOPE_profile')")
    @RequestMapping(method = RequestMethod.GET, value = "protected")
    public String protectedPoint() {
        return this.webClient
                .get()
                .uri("http://localhost:9090/sasi/service2/webapp/protected")
                .attributes(clientRegistrationId("service1-client-client-credentials"))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<String>() {
                })
                .block();
    }

}
