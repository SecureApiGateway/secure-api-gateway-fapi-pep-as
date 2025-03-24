/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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

import static com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator.Heaplet.CONFIG_OLD_TRANSPORT_KEY_USE;
import static com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator.Heaplet.CONFIG_TRANSPORT_CERT_SECRET_ID;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateExpiredX509Cert;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.secrets.Purpose.purpose;
import static org.forgerock.secrets.jwkset.JwkSetSecretStore.JwkPredicates.keyUse;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.stream.Stream;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.util.Options;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;

class DefaultTransportCertValidatorTest {

    // Actual X509 certificate
    private static X509Certificate transportCert;
    // JWKSet containing transportCert plus others.
    private static JWKSet testJwks;

    // The transport cert JWK's keyUse, and related purpose
    private static final String TRANSPORT_CERT_KEY_USE = "tls";
    private static final String TRANSPORT_CERT_LABEL = "tls";
    private static final Purpose<VerificationKey> TRANSPORT_CERT_PURPOSE =
            purpose(TRANSPORT_CERT_LABEL, VerificationKey.class);

    // It's easier to use a real JwkSetSecretStore
    private static JwkSetSecretStore jwkSetSecretStore;

    @BeforeAll
    public static void beforeAll() throws Exception {
        Pair<X509Certificate, JWKSet> transportCertPemAndJwkSet =
                CryptoUtils.generateTestTransportCertAndJwks(TRANSPORT_CERT_KEY_USE);
        transportCert = transportCertPemAndJwkSet.getFirst();
        testJwks = transportCertPemAndJwkSet.getSecond();
    }

    @Test
    void shouldFindValidCertWithTlsKeyUsePredicate() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(testJwks, Options.defaultOptions())
                .withPurposePredicate(TRANSPORT_CERT_PURPOSE, keyUse(TRANSPORT_CERT_KEY_USE));
        // ... and - validator using purpose TLS
        TransportCertValidator transportCertValidator = new DefaultTransportCertValidator(TRANSPORT_CERT_PURPOSE);
        // When/Then - cert found
        assertThatNoException()
                .isThrownBy(() -> transportCertValidator.validate(transportCert, jwkSetSecretStore)
                                                        .getOrThrowIfInterrupted());
    }

    private static Stream<DefaultTransportCertValidator> validatorWithVariousPurposeLabels() {
        return Stream.of(
                // Validator configured to use TLS transport purpose as expected transport cert purpose
                new DefaultTransportCertValidator(TRANSPORT_CERT_PURPOSE),
                // Specified, but uninteresting, purpose
                new DefaultTransportCertValidator(purpose("label", VerificationKey.class)),
                // Non-specific purpose defaults to "verify"
                new DefaultTransportCertValidator(purpose(Purpose.VERIFY_CERTIFICATE.getLabel(),
                                                          VerificationKey.class))
        );
    }

    @ParameterizedTest
    @MethodSource("validatorWithVariousPurposeLabels")
    void shouldFindValidCertWhenNoPurposeKeyUsePredicate(final DefaultTransportCertValidator validator) {
        // Given - JwkSetSecretStore not constraining any Purpose (with a predicate)
        jwkSetSecretStore = new JwkSetSecretStore(testJwks, Options.defaultOptions());
        // When/Then - cert found
        assertThatNoException()
                .isThrownBy(() -> validator.validate(transportCert, jwkSetSecretStore).getOrThrowIfInterrupted());
    }

    @Test
    void shouldFailToFindCertWhenKeyUseNotAsExpected() throws Exception {
        // Given - Alternative set of JWKs created with keyUse "misc"
        String otherKeyUse = "misc";
        Pair<X509Certificate, JWKSet> transportCertPemAndJwkSet =
                CryptoUtils.generateTestTransportCertAndJwks(otherKeyUse);
        JWKSet jwkSet = transportCertPemAndJwkSet.getSecond();
        // ... and JwkSeSecretStore expects keyUse "tls" for purpose "tls"
        jwkSetSecretStore = new JwkSetSecretStore(jwkSet, Options.defaultOptions())
                .withPurposePredicate(TRANSPORT_CERT_PURPOSE, keyUse(TRANSPORT_CERT_KEY_USE));
        // ... and - validator using purpose "tls" (so requires JWK keyUse to be "tls")
        TransportCertValidator validator = new DefaultTransportCertValidator(TRANSPORT_CERT_PURPOSE);
        // When/Then - cert matches, but its JWK keyUse is TLS, so validation fails
        assertThatThrownBy(() -> validator.validate(transportCert, jwkSetSecretStore).getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessage("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
    }

    @Test
    void shouldFailWhenCertNotInJwks() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(testJwks, Options.defaultOptions())
                .withPurposePredicate(TRANSPORT_CERT_PURPOSE, keyUse(TRANSPORT_CERT_KEY_USE));
        TransportCertValidator validator = new DefaultTransportCertValidator(TRANSPORT_CERT_PURPOSE);
        // When - non-existent (new) cert is tested,
        X509Certificate certNotInJwks = generateX509Cert(generateRsaKeyPair(), "CN=test");
        // Then - validation fails
        assertThatThrownBy(() -> validator.validate(certNotInJwks, jwkSetSecretStore)
                                           .getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessage("Failed to find JWK entry in provided JWKSet which matches the X509 cert");
    }

    @Test
    void shouldFailWhenCertIsExpired() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(testJwks, Options.defaultOptions())
                .withPurposePredicate(TRANSPORT_CERT_PURPOSE, keyUse(TRANSPORT_CERT_KEY_USE));
        TransportCertValidator validator = new DefaultTransportCertValidator(TRANSPORT_CERT_PURPOSE);
        // When - expired cert is tested,
        X509Certificate expiredCert = generateExpiredX509Cert(generateRsaKeyPair(), "CN=abc");
        // Then - validation should fail
        assertThatThrownBy(() -> validator.validate(expiredCert, jwkSetSecretStore)
                                          .getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("certificate expired on");
    }

    @Test
    void shouldFailWhenBeforeCertStartDate() {
        // Given - JwkSetSecretStore with predicate for TLS purpose, requiring keyUse TLS
        jwkSetSecretStore = new JwkSetSecretStore(testJwks, Options.defaultOptions())
                .withPurposePredicate(TRANSPORT_CERT_PURPOSE, keyUse(TRANSPORT_CERT_KEY_USE));
        TransportCertValidator validator = new DefaultTransportCertValidator(TRANSPORT_CERT_PURPOSE);
        // ... and cert with date prior to start date
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_YEAR, 5);
        Date certStartDate = calendar.getTime();
        calendar.add(Calendar.DAY_OF_YEAR, 50);
        Date certEndDate = calendar.getTime();
        X509Certificate certStartDateNotReached = generateX509Cert(generateRsaKeyPair(),
                                                                   "CN=abc",
                                                                   certStartDate,
                                                                   certEndDate);
        // Then - validation should fail
        assertThatThrownBy(() -> validator.validate(certStartDateNotReached, jwkSetSecretStore)
                                          .getOrThrowIfInterrupted())
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("certificate not valid till");
    }

    private static Stream<JsonValue> validatorConfig() {
        return Stream.of(
                // Minimal config
                json(object()),
                // 'transportCertSecretId' config
                json(object(field(CONFIG_TRANSPORT_CERT_SECRET_ID, TRANSPORT_CERT_KEY_USE))),
                // deprecated 'validKeyUse' config - treated now as a purpose
                json(object(field(CONFIG_OLD_TRANSPORT_KEY_USE, TRANSPORT_CERT_KEY_USE)))
        );
    }

    @ParameterizedTest
    @MethodSource("validatorConfig")
    void shouldSuccessfullyCreateByHeaplet(final JsonValue validatorConfig) throws Exception {
         Heaplet heaplet = new DefaultTransportCertValidator.Heaplet();
         assertThat(heaplet.create(Name.of("validator"), validatorConfig, new HeapImpl(Name.of("heap"))))
                 .isNotNull();
    }
}