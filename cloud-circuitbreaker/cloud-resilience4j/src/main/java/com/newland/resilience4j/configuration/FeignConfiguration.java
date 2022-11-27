package com.newland.resilience4j.configuration;

import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.time.Duration;
import java.util.function.Function;

/**
 * Author: leell
 * Date: 2022/11/27 00:49:13
 */
@Component
public class FeignConfiguration {
    @Resource
    Resilience4JCircuitBreakerFactory resilience4JCircuitBreakerFactory;

    @PostConstruct
    public void Setresilience4jCircuitBreakerFactory() {
        Function<String, Resilience4JConfigBuilder.Resilience4JCircuitBreakerConfiguration> defaultConfiguration = id -> new Resilience4JConfigBuilder(id)
                .circuitBreakerConfig(CircuitBreakerConfig.ofDefaults())
                .timeLimiterConfig(TimeLimiterConfig.custom().timeoutDuration(Duration.ofSeconds(10)).cancelRunningFuture(true).build())
                .build();
        resilience4JCircuitBreakerFactory.configureDefault(defaultConfiguration);
    }
}