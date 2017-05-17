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

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.ByteArrayInputStream;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

public class VerifyTest extends Assert {

    private final String privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF\n" +
            "NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F\n" +
            "UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB\n" +
            "AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA\n" +
            "QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK\n" +
            "kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg\n" +
            "f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u\n" +
            "412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc\n" +
            "mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7\n" +
            "kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA\n" +
            "gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW\n" +
            "G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI\n" +
            "7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==\n" +
            "-----END RSA PRIVATE KEY-----\n";

    private final String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3\n" +
            "6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6\n" +
            "Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw\n" +
            "oYi+1hqp1fIekaxsyQIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    private final String nonMatchingPublicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0yhBagCTmxWQvXF+70Ds\n" +
        "VY9x1U3Nm+Sgy6ka5HsyIdXGryRaOsff52joRcjAzoycYd/SwLhp2nuSkNLNPx6m\n" +
        "fykDqD2QeAk5HHGzk181/f7qZuTcf5Rj3PIWJMkNWMKzEpsfmwfRaBnh8D086Hpv\n" +
        "1Zns1OQjyvSrsxT+cCQPh0oXp2f3aT1kr8No7pOJWHmwdPQ9+ZJH0VhfPjd4sKeZ\n" +
        "lr+Aa3iL5LVgGImXeJezUEDx5i8lUmg8wsW+NsyHSmqmYxfppDPBe3dsipy2heqW\n" +
        "fLrw6IyqOg+CzH+3i5LkM+MtIwF2gMnOeAdypQYvB5af49kyq3nday2rBzGjl0PL\n" +
        "ZwIDAQAB\n" +
        "-----END PUBLIC KEY-----\n";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final RSAPublicKey nonMatchingPublicKey;

    public VerifyTest() throws Exception {
        privateKey = (RSAPrivateKey) PEM.readPrivateKey(new ByteArrayInputStream(privateKeyPem.getBytes()));
        publicKey = (RSAPublicKey) PEM.readPublicKey(new ByteArrayInputStream(publicKeyPem.getBytes()));
        nonMatchingPublicKey = (RSAPublicKey) PEM.readPublicKey(new ByteArrayInputStream(nonMatchingPublicKeyPem.getBytes()));
    }

    @Test
    public void testHmacVerifySuccess() throws Exception {
        final String keyId = "hmackey-1";
        final Algorithm algorithm = Algorithm.HMAC_SHA256;

        final Signature signature = new Signature(keyId, algorithm.getPortableName(), null, "content-length", "host", "date", "(request-target)");

        final String secretKeyString = "this-is-a-secret!";
        final Key key = new SecretKeySpec(secretKeyString.getBytes(StandardCharsets.UTF_8), algorithm.getJmvName());
        final Signer signer = new Signer(key, signature);

        final String method = "PUT";
        final String uri = "/foo/Bar";
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");
        final Signature signed = signer.sign(method, uri, headers);
        assertEquals("ELgShaON4ZIoDlekwm0FlHK8k2tMUbc03u9FJCrsQ0I=", signed.getSignature());

        // now verify - should succeed
        String signingBase = Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
        final byte[] keyBytes = secretKeyString.getBytes(StandardCharsets.UTF_8);
        final HMACSignatureVerifier verifier = new HMACSignatureVerifier(keyBytes, signature.getAlgorithm().getJmvName());
        final boolean verified = signed.verify(verifier, signingBase);
        assertTrue("verification", verified);
    }

    @Test
    public void testHmacVerifyFail() throws Exception {
        final String keyId = "hmackey-1";
        final Algorithm algorithm = Algorithm.HMAC_SHA256;

        final Signature signature = new Signature(keyId, algorithm.getPortableName(), null, "content-length", "host", "date", "(request-target)");

        final String secretKeyString = "this-is-a-secret!";
        final Key key = new SecretKeySpec(secretKeyString.getBytes(StandardCharsets.UTF_8), algorithm.getJmvName());
        final Signer signer = new Signer(key, signature);

        final String method = "POST";
        final String uri = "/foo/Bar";
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");
        final Signature signed = signer.sign(method, uri, headers);
        assertEquals("KGKBAFkH4pRUc1OKNhihff3556e6+IR9peM277b7sLM=", signed.getSignature());

        // now verify - should fail
        String signingBase = Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
        final byte[] keyBytes = "NotTheRealKey".getBytes(StandardCharsets.UTF_8);
        final HMACSignatureVerifier verifier = new HMACSignatureVerifier(keyBytes,
                                                                         signature.getAlgorithm().getJmvName());
        final boolean verified = signed.verify(verifier, signingBase);
        assertFalse("verification", verified);
    }


    @Test
    public void testRsaVerifySuccess() throws Exception {
        final String keyId = "rsakeyid-1";
        final Algorithm algorithm = Algorithm.RSA_SHA256;
        final Signature signature = new Signature(keyId, algorithm.getPortableName(), null, "content-length", "host", "date", "(request-target)");

        final Signer signer = new Signer(privateKey, signature);

        final String method = "PUT";
        final String uri = "/foo/Bar";
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");
        final Signature signed = signer.sign(method, uri, headers);
        assertEquals("iaGqwfs6zw1drOgwS5pgLwZTAF2DO1BGGMGg1/mwPwAmQu9j45wecPgBSEXg7Zv/sm+/2hF703ov3i0qSO8lwUmEjxYunS9TbBcUO2r20Z0xx+tK+KpkbS5OeALxCvIq1/O1uy3OxOQFF9xvTclPPsw42MVKoz7AWWtOQtKSuwA=", signed.getSignature());

        // now verify - should succeed
        String signingBase = Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
        final RSASignatureVerifier verifier = new RSASignatureVerifier(publicKey, signature.getAlgorithm().getJmvName());
        final boolean verified = signed.verify(verifier, signingBase);
        assertTrue("verification", verified);
    }


    @Test
    public void testRsaVerifyFail() throws Exception {
        final String keyId = "rsakeyid-1";
        final Algorithm algorithm = Algorithm.RSA_SHA256;
        final Signature signature = new Signature(keyId, algorithm.getPortableName(), null, "content-length", "host", "date", "(request-target)");

        final Signer signer = new Signer(privateKey, signature);

        final String method = "POST";
        final String uri = "/foo/Bar";
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");
        final Signature signed = signer.sign(method, uri, headers);
        assertEquals("NjQ0hwQD5fFIn/ezJHKmJEAb1ftwY0D44a1A9a8e0zR58jFhNMzZrwWiGl+re6xg0GxAdCqQbNKjSlVBXn422IgYuytXUE/RfRWKRgoOXly3bOMZIZpn0LgErf89Nq/EtiwQeG4TlKXhVhuiW4jFWONZwLkA/FMMMPW5YD1zvH0=",
                     signed.getSignature());

        // now verify - should fail
        String signingBase = Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
        final RSASignatureVerifier verifier = new RSASignatureVerifier(nonMatchingPublicKey, signature.getAlgorithm().getJmvName());
        final boolean verified = signed.verify(verifier, signingBase);
        assertFalse("verification", verified);
    }

}
