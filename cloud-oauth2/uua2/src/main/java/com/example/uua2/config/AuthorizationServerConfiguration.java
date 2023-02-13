/*
 * Copyright (c) 2020 pig4cloud Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.uua2.config;

import com.example.uua2.SecurityConstants;
import com.example.uua2.handler.CustomeOAuth2TokenCustomizer;
import com.example.uua2.handler.FormIdentityLoginConfigurer;
import com.example.uua2.handler.PigAuthenticationFailureEventHandler;
import com.example.uua2.handler.PigAuthenticationSuccessEventHandler;
import com.example.uua2.password.OAuth2UsernamePasswordAuthenticationConverter;
import com.example.uua2.password.OAuth2UsernamePasswordAuthenticationProvider;
import com.example.uua2.password.PigDaoAuthenticationProvider;
import com.example.uua2.utils.CustomeOAuth2AccessTokenGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;

/**
 * @author lengleng
 * @date 2022/5/27
 *
 * 认证服务器配置
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfiguration {
	@Autowired
	private PigDaoAuthenticationProvider pigDaoAuthenticationProvider;
	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		return registeredClientRepository;
	}
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,OAuth2AuthorizationService authorizationService) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		http.apply(authorizationServerConfigurer.tokenEndpoint((tokenEndpoint) -> {
			tokenEndpoint.accessTokenRequestConverter(accessTokenRequestConverter())
					.accessTokenResponseHandler(new PigAuthenticationSuccessEventHandler())
					.errorResponseHandler(new PigAuthenticationFailureEventHandler());
		}).clientAuthentication(oAuth2ClientAuthenticationConfigurer ->
		oAuth2ClientAuthenticationConfigurer.errorResponseHandler(new PigAuthenticationFailureEventHandler()))
				.authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
						.consentPage(SecurityConstants.CUSTOM_CONSENT_PAGE_URI)));
		RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

		DefaultSecurityFilterChain securityFilterChain = http.securityMatcher(endpointsMatcher)
				.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
				.apply(authorizationServerConfigurer.authorizationService(authorizationService)
						.authorizationServerSettings(AuthorizationServerSettings.builder()
								.issuer(SecurityConstants.PROJECT_LICENSE).build()))
				// 授权码登录的登录页个性化
				.and().apply(new FormIdentityLoginConfigurer()).and().build();

		// 注入自定义授权模式实现
		addCustomOAuth2GrantAuthenticationProvider(http);
		return securityFilterChain;
	}

	/**
	 * 令牌生成规则实现 </br>
	 * client:username:uuid
	 * @return OAuth2TokenGenerator
	 */
	@Bean
	public OAuth2TokenGenerator oAuth2TokenGenerator() {
		CustomeOAuth2AccessTokenGenerator accessTokenGenerator = new CustomeOAuth2AccessTokenGenerator();
		// 注入Token 增加关联用户信息
		accessTokenGenerator.setAccessTokenCustomizer(new CustomeOAuth2TokenCustomizer());
		return new DelegatingOAuth2TokenGenerator(accessTokenGenerator, new OAuth2RefreshTokenGenerator());
	}

	/**
	 * request -> xToken 注入请求转换器
	 * @return DelegatingAuthenticationConverter
	 */
	private AuthenticationConverter accessTokenRequestConverter() {
		return new DelegatingAuthenticationConverter(Arrays.asList(
				new OAuth2UsernamePasswordAuthenticationConverter(),
				 new OAuth2RefreshTokenAuthenticationConverter(),
				new OAuth2ClientCredentialsAuthenticationConverter(),
				new OAuth2AuthorizationCodeAuthenticationConverter(),
				new OAuth2AuthorizationCodeRequestAuthenticationConverter()));
	}

	/**
	 * 注入授权模式实现提供方
	 *
	 * 1. 密码模式 </br>
	 * 2. 短信登录 </br>
	 *
	 */
	@SuppressWarnings("unchecked")
	private void addCustomOAuth2GrantAuthenticationProvider(HttpSecurity http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);

		OAuth2UsernamePasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider = new OAuth2UsernamePasswordAuthenticationProvider(
				authenticationManager, authorizationService, oAuth2TokenGenerator());

		// 处理 UsernamePasswordAuthenticationToken
		http.authenticationProvider(pigDaoAuthenticationProvider);
		// 处理 OAuth2ResourceOwnerPasswordAuthenticationToken
		http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
		// 处理 OAuth2ResourceOwnerSmsAuthenticationToken
	}

}
