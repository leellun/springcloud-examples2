/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.newland.auth.config;

import com.newland.auth.config.core.AuthOAuth2TokenCustomizer;
import com.newland.auth.config.jwt.JwtAccessTokenGenerator;
import com.newland.auth.config.jwt.JwtRefreshTokenGenerator;
import com.newland.auth.config.password.AuthOAuth2AccessTokenGenerator;
import com.newland.auth.utils.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 默认配置
 * @author leell
 */
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    public static void main(String[] args) {
        DefaultSecurityConfig config = new DefaultSecurityConfig();
        JwtDecoder jwtDecoder = config.jwtDecoder(config.jwkSource());
        Jwt jwt = jwtDecoder.decode("eyJraWQiOiI4ZWQ3OGFlOS05MGEwLTRjY2MtYTE4ZC0xMjExMDUxM2MwODUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NzYzODY0NDAsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJtZXNzYWdlLnJlYWQiLCJtZXNzYWdlLndyaXRlIl0sImlzcyI6Imh0dHBzOi8vcGlnNGNsb3VkLmNvbSIsImV4cCI6MTc4NzQ5NzU1MSwiaWF0IjoxNjc2Mzg2NDQwLCJqdGkiOiJlMjYxZDY5YS0wMTlhLTQxMTEtYmVkNS05ZTExOGFjNzk0YzYifQ.NxSVNnU07TH9NVRtBQq9fGLwYgbhwy4iCpMlNKUFmCeJNLUbHNos9tGEZkgppHtKker8S7KyF6f2y2l2zq2lRLKNQrjV5-P3AKmYmArHdYmZZkUFi9Ne-zcKudo0q_K67HLWccXNXjJ_qrWRNosTqv89Ktg8tK7spBX93_g8mnTtwgt-UYcFhcffYd9S5udFffCNOh321LbC10LWGFoeUxSGjh7yYE7g9m2YJ7Ce29VmRjVx1OXq-ihtvbQ7BCMEoTJxYubl5dUtrgHeZVAf40e_jfVC_Oyg9CF-YMcdHH32mnIxXULI5scr8AnC3u4xcuPaaApmRIPvVOd3ch991g");
        System.out.println(jwt);
    }

//    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123456")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public OAuth2TokenGenerator createAuth2TokenGenerator(JwtEncoder jwtEncoder) {
        AuthOAuth2AccessTokenGenerator authOAuth2AccessTokenGenerator = new AuthOAuth2AccessTokenGenerator();
        // 注入Token 增加关联用户信息
        authOAuth2AccessTokenGenerator.setAccessTokenCustomizer(new AuthOAuth2TokenCustomizer());
        return new DelegatingOAuth2TokenGenerator(authOAuth2AccessTokenGenerator, new JwtAccessTokenGenerator(jwtEncoder), new JwtRefreshTokenGenerator(jwtEncoder), new OAuth2RefreshTokenGenerator());
    }
}
