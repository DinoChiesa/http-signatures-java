/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe.auth.signatures;

import javax.crypto.Mac;
import java.security.Key;
import java.security.Provider;
import java.nio.charset.StandardCharsets;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;
import java.util.Arrays;
import static java.util.Objects.requireNonNull;

/**
 * HMACSignatureVerifier is multi-thread safe.
 *
 */
public class HMACSignatureVerifier implements SignatureVerifier {
    private final Key key;
    private final String algorithmName;
    private final Provider provider;
    private final static List<String> supportedAlgorithms = Arrays.asList("HmacSHA256", "HmacSHA384", "HmacSHA512" );

    public HMACSignatureVerifier(final byte[] keyBytes, final String algorithmName) {
        this(keyBytes, algorithmName, null);
    }

    public HMACSignatureVerifier(final byte[] keyBytes, final String algorithmName, final Provider provider) {
        requireNonNull(keyBytes, "keyBytes cannot be null");
        this.provider = provider;
        this.algorithmName = algorithmName;
        if (supportedAlgorithms.indexOf(algorithmName)<0) {
            throw new UnsupportedAlgorithmException(algorithmName);
        }
        this.key = new SecretKeySpec(keyBytes, algorithmName);
    }

    @Override
    public boolean verify(final String signedContent, final String signature) {
        try {
            byte[] bytes = signedContent.getBytes(StandardCharsets.UTF_8);
            return verify(bytes, signature);
        } catch (Exception exc1) {
            return false;
        }
    }

    @Override
    public boolean verify(final byte[] signedContent, final String signature) {
        try {
            final Mac mac = provider == null ?
                Mac.getInstance(algorithmName) :
                Mac.getInstance(algorithmName, provider);
            mac.init(key);
            mac.update(signedContent);
            final byte[] binarySignature = mac.doFinal();
            final byte[] encoded = Base64.encodeBase64(binarySignature);
            final String computedSignature = new String(encoded, StandardCharsets.UTF_8);
            return computedSignature.equals(signature);
        } catch (Exception exc1) {
            return false;
        }
    }
}
