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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.filter.TransportCertValidationFilter.x509CertsEqual;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Status.BAD_REQUEST;
import static org.forgerock.http.protocol.Status.TEAPOT;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_CLIENT_METADATA;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_SOFTWARE_STATEMENT;
import static org.forgerock.openig.fapi.jwks.JwkSetServicePurposes.transportPurpose;
import static org.forgerock.secrets.jwkset.JwkSetSecretStore.JwkPredicates.keyUse;
import static org.forgerock.util.Options.defaultOptions;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.KeyUseConstants;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.util.Choice;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.util.CryptoUtils;

@ExtendWith(MockitoExtension.class)
public class TransportCertValidationFilterTest {
    private static final URI JWKS_URI = URI.create("https://www.fintech.com/jwks");
    private static final String REQUEST_URI = "https://ig.example.com/am/register/1234";
    private static final String TRANSPORT_CERT_KEY_USE = "tls";
    private static final String OTHER_CERT_KEY_USE = "sig";

    // Actual X509 certificate
    private static X509Certificate tlsClientCert;
    // JWKSet containing transportCert plus others.
    private static JWKSet jwkSet;
    private static JwkSetSecretStore jwkSetSecretStore;

    @Mock
    JwkSetService jwkSetService;
    @Mock
    private RegistrationRequest registrationRequest;
    @Mock
    private SoftwareStatement softwareStatement;
    @Mock
    private ApiClient apiClient;
    @Mock
    private Handler next;

    @Captor
    private ArgumentCaptor<JsonValue> jwksCaptor;

    private FapiContext fapiContext;
    private Request request;

    @BeforeAll
    static void setUpSecretsAndJwks() throws Exception {
        Pair<X509Certificate, JWKSet> transportCertPemAndJwkSet =
                CryptoUtils.generateTestTransportCertAndJwks(TRANSPORT_CERT_KEY_USE);
        tlsClientCert = transportCertPemAndJwkSet.getFirst();
        jwkSet = transportCertPemAndJwkSet.getSecond();
        jwkSetSecretStore = new JwkSetSecretStore(jwkSet, defaultOptions());
    }

    @BeforeEach
    void setUp() throws Exception {
        fapiContext = new FapiContext(new RootContext());
        fapiContext.setRegistrationRequest(registrationRequest);
        fapiContext.setClientCertificates(tlsClientCert);
        fapiContext.setApiClient(apiClient);
        request = new Request().setMethod("GET")
                               .setUri(REQUEST_URI);
    }

    @Test
    void shouldFailIfNoFapiContext() {
        // Given
        Filter filter = new TransportCertValidationFilter(jwkSetService, false);
        // When/ Then
        assertThatThrownBy(() -> filter.filter(new RootContext(), request, next)
                                       .getOrThrowIfInterrupted())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("FapiContext not found");
    }

    @Test
    void shouldFindValidCertInJwksUri() {
        // Given - Registration SSA uses JWKS URI which contains "tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue1(JWKS_URI));
        when(jwkSetService.getJwkSetSecretStore(any())).thenReturn(newResultPromise(jwkSetSecretStore));
        when(next.handle(any(), any())).thenReturn(newResponsePromise(new Response(TEAPOT)));
        Filter filter = new TransportCertValidationFilter(jwkSetService, false);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert found
        verify(next).handle(eq(fapiContext), eq(request));
        verify(registrationRequest).setMetadata(eq("jwks_uri"), eq(JWKS_URI.toASCIIString()));
        assertThat(response.getStatus()).isEqualTo(TEAPOT);
    }

    @Test
    void shouldFindValidCertInJwkSet() {
        // Given - Registration SSA uses JWKSet which contains "tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
        when(next.handle(any(), any())).thenReturn(newResponsePromise(new Response(TEAPOT)));
        // ... and - filter configured to support IG-issued certs(JWKSet)
        Filter filter = new TransportCertValidationFilter(jwkSetService, true);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert found
        assertThat(response.getStatus()).isEqualTo(TEAPOT);
        verify(next).handle(eq(fapiContext), eq(request));
        verify(registrationRequest).setMetadata(eq("jwks"), jwksCaptor.capture());
        assertThat(jwksCaptor.getValue().toString()).isEqualTo(jwkSet.toJsonValue().toString());
    }

    @Test
    void shouldPreventUseOfJwkSetUnlessConfigured() throws IOException {
        // Given - Registration SSA uses JWKSet which contains "tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
        // ... but - filter not configured to support IG-issued certs(JWKSet)
        Filter filter = new TransportCertValidationFilter(jwkSetService, false);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert validation fails
        verifyNoInteractions(next);
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies((entityJson -> {
                    assertThat(entityJson.get("error").asString())
                            .isEqualTo(INVALID_CLIENT_METADATA.getCode());
                    assertThat(entityJson.get("error_description").asString())
                            .isEqualTo("software_statement must contain software_jwks_endpoint");
                }));
    }

    @Test
    void shouldReturnErrorResponseWhenCertNotPresentInJwksUri() throws IOException {
        // Given - Registration SSA uses JWKS URI which contains "tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue1(JWKS_URI));
        when(jwkSetService.getJwkSetSecretStore(any())).thenReturn(newResultPromise(jwkSetSecretStore));
        Filter filter = new TransportCertValidationFilter(jwkSetService, false);
        // ... and - FapiContext contains a cert not in JWKS
        X509Certificate certNotInJwks = generateX509Cert(generateRsaKeyPair(), "CN=test");
        fapiContext.setClientCertificates(certNotInJwks);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert validation fails
        verifyNoInteractions(next);
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies((entityJson -> {
                    assertThat(entityJson.get("error").asString())
                            .isEqualTo(INVALID_SOFTWARE_STATEMENT.getCode());
                    assertThat(entityJson.get("error_description").asString())
                            .isEqualTo("tls transport cert does not match any certs " +
                                               "registered in jwks for software statement");
                }));
    }

    @Test
    void shouldReturnErrorResponseWhenCertNotPresentInJwkSet() throws IOException {
        // Given - Registration SSA uses JWKSet which contains "tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet));
        // ... and - filter configured to support IG-issued certs(JWKSet)
        Filter filter = new TransportCertValidationFilter(jwkSetService, true);
        // ... and - FapiContext contains a cert not in JWKS
        X509Certificate certNotInJwks = generateX509Cert(generateRsaKeyPair(), "CN=test");
        fapiContext.setClientCertificates(certNotInJwks);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert validation fails
        verifyNoInteractions(next);
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies((entityJson -> {
                    assertThat(entityJson.get("error").asString())
                            .isEqualTo(INVALID_SOFTWARE_STATEMENT.getCode());
                    assertThat(entityJson.get("error_description").asString())
                            .isEqualTo("tls transport cert does not match any certs " +
                                               "registered in jwks for software statement");
                }));
    }

    @Test
    void shouldReturnErrorResponseWhenCertPresentWithDifferentJwkUseInJwksUri() throws Exception {
        // Given - new cert and JWKS where matching cert JWK has 'use' other than 'tls'
        Pair<X509Certificate, JWKSet> otherCertPemAndJwkSet =
                CryptoUtils.generateTestTransportCertAndJwks(OTHER_CERT_KEY_USE);
        X509Certificate otherClientCert = otherCertPemAndJwkSet.getFirst();
        // ... and - JwkSetSecretStore configured as per real CachingJwkSetService impl
        JwkSetSecretStore jwkSetSecretStore2 =
                new JwkSetSecretStore(otherCertPemAndJwkSet.getSecond(), defaultOptions())
                        .withPurposePredicate(transportPurpose(), keyUse(KeyUseConstants.TLS));
        // ... and - Registration SSA uses JWKS URI which contains non-"tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue1(JWKS_URI));
        when(jwkSetService.getJwkSetSecretStore(any())).thenReturn(newResultPromise(jwkSetSecretStore2));
        // ... and - FapiContext contains cert matching JWK with other use
        fapiContext.setClientCertificates(otherClientCert);
        Filter filter = new TransportCertValidationFilter(jwkSetService, false);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert validation fails
        verifyNoInteractions(next);
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies((entityJson -> {
                    assertThat(entityJson.get("error").asString())
                            .isEqualTo(INVALID_SOFTWARE_STATEMENT.getCode());
                    assertThat(entityJson.get("error_description").asString())
                            .isEqualTo("tls transport cert does not match any certs " +
                                               "registered in jwks for software statement");
                }));
    }

    @Test
    void shouldReturnErrorResponseWhenCertPresentWithDifferentJwkUseInJwkSet() throws Exception {
        // Given - new cert and JWKS where matching cert JWK has 'use' other than 'tls'
        Pair<X509Certificate, JWKSet> otherCertPemAndJwkSet =
                CryptoUtils.generateTestTransportCertAndJwks(OTHER_CERT_KEY_USE);
        X509Certificate otherClientCert = otherCertPemAndJwkSet.getFirst();
        JWKSet jwkSet2 = otherCertPemAndJwkSet.getSecond();
        // ... and - Registration SSA uses JWKSet which contains non-"tls" cert
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getJwkSetLocator()).thenReturn(Choice.withValue2(jwkSet2));
        // ... and - FapiContext contains cert matching JWK with other use
        fapiContext.setClientCertificates(otherClientCert);
        Filter filter = new TransportCertValidationFilter(jwkSetService, true);
        // When
        Response response = filter.filter(fapiContext, request, next).getOrThrowIfInterrupted();
        // Then - cert validation fails
        verifyNoInteractions(next);
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies((entityJson -> {
                    assertThat(entityJson.get("error").asString())
                            .isEqualTo(INVALID_SOFTWARE_STATEMENT.getCode());
                    assertThat(entityJson.get("error_description").asString())
                            .isEqualTo("tls transport cert does not match any certs " +
                                               "registered in jwks for software statement");
                }));
    }

    @Test
    void shouldConsiderSameCertAsEqual() {
        assertThat(x509CertsEqual(tlsClientCert, tlsClientCert)).isTrue();
    }

    @Test
    void shouldConsiderCertComparisonWithNullAsUnequal() {
        assertThat(x509CertsEqual(tlsClientCert, null)).isFalse();
    }

    @Test
    void shouldConsiderCertEncodingErrorAsUnequal() throws CertificateEncodingException {
        X509Certificate mockCert = mock(X509Certificate.class);
        when(mockCert.getEncoded()).thenThrow(new CertificateEncodingException());
        // When/ Then
        assertThat(x509CertsEqual(mockCert, mockCert)).isFalse();
    }

    @Nested
    class HeapletTests {
        private static HeapImpl heap;

        @BeforeAll
        static void buildHeap() {
            heap = new HeapImpl(Name.of("heap"));
            heap.put("jwkSetService1", mock(JwkSetService.class));
        }

        static Stream<JsonValue> validConfigurations() {
            return Stream.of(
                    // Full config
                    json(object(field("jwkSetService", "jwkSetService1"),
                                field("allowIgIssuedTestCerts", true))),
                    // Minimal cofig
                    json(object(field("jwkSetService", "jwkSetService1"))));
        }

        @ParameterizedTest
        @MethodSource("validConfigurations")
        void shouldSuccessfullyCreateTransportCertValidationFilter(final JsonValue config) throws HeapException {
            TransportCertValidationFilter.Heaplet heaplet = new TransportCertValidationFilter.Heaplet();
            assertThat(heaplet.create(Name.of("transportCertFilter"), config, heap)).isNotNull();
        }

        static Stream<JsonValue> invalidConfigurations() {
            return Stream.of(
                    // Missing 'jwkSetService' config
                    json(object(field("allowIgIssuedTestCerts", true))),
                    // No config
                    json(object()));
        }

        @ParameterizedTest
        @MethodSource("invalidConfigurations")
        void shouldFailToCreateTransportCertValidationFilter(final JsonValue config) throws HeapException {
            TransportCertValidationFilter.Heaplet heaplet = new TransportCertValidationFilter.Heaplet();
            assertThatThrownBy(() -> heaplet.create(Name.of("transportCertFilter"), config, heap))
                    .isInstanceOf(HeapException.class)
                    .cause()
                    .isInstanceOf(JsonValueException.class)
                    .hasMessage("/jwkSetService: Expecting a value");
        }
    }
}
