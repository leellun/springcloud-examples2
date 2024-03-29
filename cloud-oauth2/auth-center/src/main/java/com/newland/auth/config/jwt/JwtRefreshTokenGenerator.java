package com.newland.auth.config.jwt;

import com.newland.auth.common.AuthConstant;
import com.newland.auth.common.GrantType;
import com.newland.auth.common.TokenType;
import com.newland.auth.model.AuthUser;
import com.newland.auth.model.LoginUser;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

/**
 * jwt刷新
 * Author: leell
 * Date: 2023/2/15 15:26:42
 */
public class JwtRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
    private final JwtEncoder jwtEncoder;

    public JwtRefreshTokenGenerator(@NonNull JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @Nullable
    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!TokenType.JWT_REFRESH_TOKEN.getValue().equals(context.getTokenType().getValue())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        RegisteredClient registeredClient = context.getRegisteredClient();
        String issuer = null;
        if (context.getAuthorizationServerContext() != null) {
            issuer = context.getAuthorizationServerContext().getIssuer();
        }
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer);
        }
        AuthUser authUser = (AuthUser) context.getPrincipal().getPrincipal();
        LoginUser loginUser = authUser.getLoginUser();
        claimsBuilder
                .subject(context.getPrincipal().getName())
                .claim(AuthConstant.PRINCIPAL,loginUser)
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
        }
        JwtClaimsSet jwtClaimsSet = claimsBuilder.build();
        return new OAuth2RefreshToken(this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue(), issuedAt, expiresAt);
    }

}
