package com.newland.auth.config.jwt;

import com.newland.auth.common.GrantType;
import com.newland.auth.common.TokenType;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * token构建起
 *
 * @author leellun
 */
public class JwtAccessTokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {
    private final JwtEncoder jwtEncoder;

    public JwtAccessTokenGenerator(@NonNull JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @Nullable
    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        if (!TokenType.JWT.getValue().equals(context.getTokenType().getValue())) {
            return null;
        }
        String issuer = null;
        if (context.getAuthorizationServerContext() != null) {
            issuer = context.getAuthorizationServerContext().getIssuer();
        }
        RegisteredClient registeredClient = context.getRegisteredClient();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            claimsBuilder.issuer(issuer);
        }
        claimsBuilder
                .subject(context.getPrincipal().getName())
                .claim("principal",context.getPrincipal())
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
        }

        JwtClaimsSet jwtClaimsSet = claimsBuilder.build();
        return new OAuth2AccessTokenClaims(OAuth2AccessToken.TokenType.BEARER,
                this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue(), jwtClaimsSet.getIssuedAt(), jwtClaimsSet.getExpiresAt(),
                context.getAuthorizedScopes(), jwtClaimsSet.getClaims());
    }

    private static final class OAuth2AccessTokenClaims extends OAuth2AccessToken implements ClaimAccessor {

        private final Map<String, Object> claims;

        private OAuth2AccessTokenClaims(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt,
                                        Set<String> scopes, Map<String, Object> claims) {
            super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
            this.claims = claims;
        }

        @Override
        public Map<String, Object> getClaims() {
            return this.claims;
        }

    }

}
