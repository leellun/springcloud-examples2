/*
 * Copyright 2020-2021 the original author or authors.
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
package com.newland.uua.utils;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
public final class Jwks {

    private Jwks() {
    }

    public static RSAKey generateRsa() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(ClassLoader.getSystemResourceAsStream("oauth2.jks"), "123456".toCharArray());
            Certificate certificate = keyStore.getCertificate("oauth2");
            KeyPair keyPair = new KeyPair(certificate.getPublicKey(), (PrivateKey) keyStore.getKey("oauth2", "123456".toCharArray()));
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID("8ed78ae9-90a0-4ccc-a18d-12110513c085")
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ECKey generateEc() {
        KeyPair keyPair = KeyGeneratorUtils.generateEcKey();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        Curve curve = Curve.forECParameterSpec(publicKey.getParams());
        // @formatter:off
        return new ECKey.Builder(curve, publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }

    public static OctetSequenceKey generateSecret() {
        SecretKey secretKey = KeyGeneratorUtils.generateSecretKey();
        // @formatter:off
        return new OctetSequenceKey.Builder(secretKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }
}
