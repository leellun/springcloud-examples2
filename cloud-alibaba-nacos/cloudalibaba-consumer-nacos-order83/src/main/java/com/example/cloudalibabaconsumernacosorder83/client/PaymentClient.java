package com.example.cloudalibabaconsumernacosorder83.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(value = "nacos-payment-provider", fallback = PaymentClientFallback.class)
public interface PaymentClient {
    @GetMapping(value = "/payment/nacos/{id}")
    public String getPayment(@PathVariable("id") Long id);
}
