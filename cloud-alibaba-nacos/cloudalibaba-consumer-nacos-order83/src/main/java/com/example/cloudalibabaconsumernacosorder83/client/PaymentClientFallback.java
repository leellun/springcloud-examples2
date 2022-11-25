package com.example.cloudalibabaconsumernacosorder83.client;

import org.springframework.stereotype.Component;

@Component
public class PaymentClientFallback implements PaymentClient{
    @Override
    public String getPayment(Long id) {
        return "获取支付信息失败";
    }
}
