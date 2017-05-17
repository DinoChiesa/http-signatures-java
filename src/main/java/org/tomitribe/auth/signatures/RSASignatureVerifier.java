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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Arrays;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import static java.util.Objects.requireNonNull;

/**
 * RSASignatureVerifier is multi-thread safe.
 *
 */
public class RSASignatureVerifier implements SignatureVerifier {

    private final RSAPublicKey publicKey;
    private final String algorithmName;
    private final Provider provider;
    private final static List<String> supportedAlgorithms = Arrays.asList("SHA256withRSA", "SHA384withRSA", "SHA512withRSA" );

    public RSASignatureVerifier(final RSAPublicKey publicKey, final String algorithmName) {
        this(publicKey, algorithmName, null);
    }

    public RSASignatureVerifier(final RSAPublicKey publicKey, final String algorithmName, final Provider provider) {
        requireNonNull(publicKey, "publicKey cannot be null");
        this.publicKey = publicKey;
        this.provider = provider;
        this.algorithmName = algorithmName;
        if (supportedAlgorithms.indexOf(algorithmName)<0) {
            throw new UnsupportedAlgorithmException(algorithmName);
        }
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
            Signature verifier = (provider == null) ?
                Signature.getInstance(algorithmName) :
                Signature.getInstance(algorithmName, provider);

            verifier.initVerify(publicKey);
            verifier.update(signedContent);
            final byte[] sigBytes = Base64.decodeBase64(signature.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(sigBytes);
        } catch (Exception exc1) {
            return false;
        }
    }
}
