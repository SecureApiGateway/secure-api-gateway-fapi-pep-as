/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.mtls;

import static com.forgerock.sapi.gateway.util.CryptoUtils.generateExpiredX509Cert;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;

class DefaultTransportCertValidatorTest {

    private static X509Certificate TEST_TLS_CERT;
    private static JWKSet TEST_JWKS;

    public static final String TLS_KEY_USE = "tls";

    @BeforeAll
    public static void beforeAll() throws Exception {
        final Pair<X509Certificate, JWKSet> transportCertPemAndJwkSet = CryptoUtils.generateTestTransportCertAndJwks(TLS_KEY_USE);
        TEST_TLS_CERT = transportCertPemAndJwkSet.getFirst();
        TEST_JWKS = transportCertPemAndJwkSet.getSecond();
    }

    @Test
    void testValidCertAndUse() throws CertificateException {
        new DefaultTransportCertValidator(TLS_KEY_USE).validate(TEST_TLS_CERT, TEST_JWKS);
    }

    @Test
    void testValidCertNoUseCheck() throws CertificateException {
        new DefaultTransportCertValidator().validate(TEST_TLS_CERT, TEST_JWKS);
    }

    @Test
    void failsWhenCertMatchButUseDoesNot() {
        final DefaultTransportCertValidator validator = new DefaultTransportCertValidator("blah");
        failsWhenCertMatchButUseDoesNot(validator);
    }

    private static void failsWhenCertMatchButUseDoesNot(DefaultTransportCertValidator validator) {
        final CertificateException certificateException = Assertions.assertThrows(CertificateException.class,
                () -> validator.validate(TEST_TLS_CERT, TEST_JWKS));

        Assertions.assertEquals("Failed to find JWK entry in provided JWKSet which matches the X509 cert", certificateException.getMessage());
    }

    @Test
    void failsWhenCertNotInJwks() {
        final X509Certificate certNotInJwks = generateX509Cert(generateRsaKeyPair(), "CN=test");
        final CertificateException certificateException = Assertions.assertThrows(CertificateException.class,
                () -> new DefaultTransportCertValidator(TLS_KEY_USE).validate(certNotInJwks, TEST_JWKS));
        Assertions.assertEquals("Failed to find JWK entry in provided JWKSet which matches the X509 cert",
                certificateException.getMessage());
    }

    @Test
    void failsWhenCertIsExpired() {
        final X509Certificate expiredCert = generateExpiredX509Cert(generateRsaKeyPair(), "CN=abc");
        final CertificateException certificateException = Assertions.assertThrows(CertificateException.class,
                () -> new DefaultTransportCertValidator("blah").validate(expiredCert, TEST_JWKS));
        assertThat(certificateException.getMessage()).contains("certificate expired on");
    }

    @Test
    void failsWhenBeforeCertStartDate() {
        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_YEAR, 5);
        final Date certStartDate = calendar.getTime();
        calendar.add(Calendar.DAY_OF_YEAR, 50);
        final Date certEndDate = calendar.getTime();

        final X509Certificate certStartDateNotReached = generateX509Cert(generateRsaKeyPair(), "CN=abc", certStartDate, certEndDate);
        final CertificateException certificateException = Assertions.assertThrows(CertificateException.class,
                () -> new DefaultTransportCertValidator("blah").validate(certStartDateNotReached, TEST_JWKS));
        assertThat(certificateException.getMessage()).contains("certificate not valid till");
    }

    @Test
    void testSuccessfullyCreatedByHeaplet() throws Exception {
        final Name name = Name.of("test");
        final HeapImpl heap = new HeapImpl(name);
        final DefaultTransportCertValidator validatorNoUseCheck = (DefaultTransportCertValidator) new Heaplet().create(name, json(object()), heap);
        validatorNoUseCheck.validate(TEST_TLS_CERT, TEST_JWKS);

        final DefaultTransportCertValidator validatorTlsUseCheck = (DefaultTransportCertValidator) new Heaplet().create(name,
                json(object(field("validKeyUse", TLS_KEY_USE))), heap);
        validatorTlsUseCheck.validate(TEST_TLS_CERT, TEST_JWKS);

        final DefaultTransportCertValidator validatorUnknownKeyUse= (DefaultTransportCertValidator) new Heaplet().create(name,
                json(object(field("validKeyUse", "unknown"))), heap);
        failsWhenCertMatchButUseDoesNot(validatorUnknownKeyUse);
    }
}