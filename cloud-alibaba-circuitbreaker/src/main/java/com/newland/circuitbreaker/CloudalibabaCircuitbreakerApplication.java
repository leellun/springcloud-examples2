package com.newland.circuitbreaker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class CloudalibabaCircuitbreakerApplication {

    public static void main(String[] args) {
        SpringApplication.run(CloudalibabaCircuitbreakerApplication.class, args);
    }

}
