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

import static com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter.Heaplet.CONFIG_CERT_HEADER;
import static com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter.Heaplet.CONFIG_CERT_RETRIEVER;
import static com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter.Heaplet.CONFIG_CERT_VALIDATOR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.mtls.HeaderCertificateRetriever;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.Options;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter.Heaplet;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

@ExtendWith(MockitoExtension.class)
class TransportCertValidationFilterTest {

    public static final String CERTIFICATE_HEADER_NAME = "ssl-client-cert";

    // It's easier to use a real JwkSetSecretStore
    private static JwkSetSecretStore jwkSetSecretStore;

    @Mock
    private TransportCertValidator transportCertValidator;
    @Mock
    private HeaderCertificateRetriever certificateResolver;
    @Mock
    private ApiClient testApiClient;
    @Mock
    private X509Certificate clientCert;
    private final Request request = new Request().setMethod("GET");

    @BeforeAll
    public static void setUpSecrets() {
        jwkSetSecretStore = new JwkSetSecretStore(new JWKSet(), Options.defaultOptions());
    }

    @Test
    public void shouldSucceedWhenCertIsValid() throws CertificateException {
        // Given - transportCertValidationFilter configured with a HeaderCertificateRetriever
        TransportCertValidationFilter transportCertValidationFilter =
                new TransportCertValidationFilter(certificateResolver, transportCertValidator);
        when(testApiClient.getJwkSetSecretStore()).thenReturn(newResultPromise(jwkSetSecretStore));
        when(transportCertValidator.validate(eq(clientCert), eq(jwkSetSecretStore)))
                .thenReturn(newResultPromise(null));
        when(certificateResolver.retrieveCertificate(any(), any())).thenReturn(clientCert);
        Context context = attrContextWithApiClient(testApiClient);
        TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
        // When
        Response response = transportCertValidationFilter.filter(context, request, nextHandler)
                                                         .getOrThrowIfInterrupted();
        // Then
        assertEquals(200, response.getStatus().getCode(), "HTTP Response Code");
        assertTrue(nextHandler.hasBeenInteractedWith(), "ResponseHandler must be called");
    }

    @Test
    public void shouldFailureIfCertHeaderNotProvided() throws Exception {
        // Given - transportCertValidationFilter configured with a HeaderCertificateRetriever
        TransportCertValidationFilter transportCertValidationFilter =
                new TransportCertValidationFilter(certificateResolver, transportCertValidator);
        // ... and request cert resolves to no cert header
        when(certificateResolver.retrieveCertificate(any(), any()))
                .thenThrow(new CertificateException("Client mTLS certificate not provided"));
        Context context = attrContextWithApiClient(testApiClient);
        TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
        // When
        Response response = transportCertValidationFilter.filter(context, request, nextHandler)
                                                         .getOrThrowIfInterrupted();
        // Then
        assertErrorResponse(response, "client tls certificate must be provided as a valid x509 certificate",
                            nextHandler);
    }

    @Test
    public void shouldFailureIfCertHeaderValueCorrupt() throws Exception {
        // Given - transportCertValidationFilter configured with a HeaderCertificateRetriever
        final TransportCertValidationFilter transportCertValidationFilter
                = new TransportCertValidationFilter(certificateResolver, transportCertValidator);
        // ... and request cert fails with decoding error
        when(certificateResolver.retrieveCertificate(any(), any()))
                .thenThrow(new CertificateException("Failed to URL decode certificate header"
                                                            + " value. Expect certificate in PEM"
                                                            + " encoded then URL encoded format"));
        Context context = attrContextWithApiClient(testApiClient);
        TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
        // When
        Response response = transportCertValidationFilter.filter(context, request, nextHandler)
                                                         .getOrThrowIfInterrupted();
        // Then
        assertErrorResponse(response, "client tls certificate must be provided as a valid x509 certificate",
                            nextHandler);
    }

    @Test
    public void shouldFailIfApiClientNotPresentInContext() throws CertificateException {
        // Given - transportCertValidationFilter configured with a HeaderCertificateRetriever, but no API client
        TransportCertValidationFilter transportCertValidationFilter =
                new TransportCertValidationFilter(certificateResolver, transportCertValidator);
        when(certificateResolver.retrieveCertificate(any(), any())).thenReturn(clientCert);
        // ... and no ApiClient on the context
        Context context = new AttributesContext(new RootContext());
        TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
        // When/ Then
        assertThatThrownBy(() -> transportCertValidationFilter.filter(context, request, nextHandler)
                                                         .getOrThrowIfInterrupted())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Required attribute: \"apiClient\" not found in context");
    }

    @Test
    public void shouldFailIfApiClientJwkSetCannotBeRetrieved() throws Exception {
        // Given - transportCertValidationFilter configured with a HeaderCertificateRetriever
        TransportCertValidationFilter transportCertValidationFilter =
                new TransportCertValidationFilter(certificateResolver, transportCertValidator);
        when(certificateResolver.retrieveCertificate(any(), any())).thenReturn(clientCert);
        // ... and JWKS loading fails
        when(testApiClient.getJwkSetSecretStore())
                .thenReturn(newExceptionPromise(new FailedToLoadJWKException("Failed to load JWKS")));
        Context context = attrContextWithApiClient(testApiClient);
        TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
        // When
        Response response = transportCertValidationFilter.filter(context, request, nextHandler)
                                                         .getOrThrowIfInterrupted();
        // Then
        assertErrorResponse(response, "Failed to get client JWKSet", nextHandler);
    }

    @Test
    public void shouldFailWhenCertNotInJwks() throws Exception {
        // Given - transportCertValidationFilter configured with a HeaderCertificateRetriever
        TransportCertValidationFilter transportCertValidationFilter =
                new TransportCertValidationFilter(certificateResolver, transportCertValidator);
        when(testApiClient.getJwkSetSecretStore()).thenReturn(newResultPromise(jwkSetSecretStore));
        when(certificateResolver.retrieveCertificate(any(), any())).thenReturn(clientCert);
        // ... and transportCertValidator validation fails to find JWK
        when(transportCertValidator.validate(any(), eq(jwkSetSecretStore)))
                .thenReturn(newExceptionPromise(new CertificateException(
                        "Failed to find JWK entry in provided JWKSet which matches the X509 cert")));
        Context context = attrContextWithApiClient(testApiClient);
        TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
        // When
        Response response = transportCertValidationFilter.filter(context, request, nextHandler)
                                                         .getOrThrowIfInterrupted();
        // Then
        assertErrorResponse(response, "client tls certificate not found in JWKS for software statement", nextHandler);
    }

    @Nested
    public class HeapletTests {

        private static Stream<Arguments> invalidConfigurations() {
            return Stream.of(
                    // Missing required CONFIG_CERT_VALIDATOR field
                    arguments(json(object(field(CONFIG_CERT_RETRIEVER, "HeaderCertificateRetriever"))),
                              "/%s: Expecting a value".formatted(CONFIG_CERT_VALIDATOR)),
                    // Missing required CONFIG_CERT_RETRIEVER or CONFIG_CERT_HEADER field
                    arguments(json(object(field(CONFIG_CERT_VALIDATOR, "TransportCertValidator"))),
                              "/%s: Expecting a value".formatted(CONFIG_CERT_RETRIEVER)));
        }

        @ParameterizedTest
        @MethodSource("invalidConfigurations")
        void shouldFailToConstructFilterWithInvalidConfig(final JsonValue config, final String expectedExceptionMessage) {
            final Name test = Name.of("test");
            HeapImpl heap = new HeapImpl(test);
            heap.put("HeaderCertificateRetriever", certificateResolver);
            heap.put("TransportCertValidator", transportCertValidator);
            Heaplet heaplet = new Heaplet();
            assertThatThrownBy(() -> heaplet.create(test, config, heap))
                    .isInstanceOf(JsonValueException.class)
                    .hasMessage(expectedExceptionMessage);
        }

        @SuppressWarnings("deprecated")
        private static Stream<JsonValue> validConfigurations() {
            return Stream.of(
                    // Full config
                    json(object(field(CONFIG_CERT_RETRIEVER, "HeaderCertificateRetriever"),
                                field(CONFIG_CERT_VALIDATOR, "TransportCertValidator"))),
                    // Deprecated config
                    json(object(field(CONFIG_CERT_HEADER, CERTIFICATE_HEADER_NAME),
                                field(CONFIG_CERT_VALIDATOR, "TransportCertValidator"))));
        }

        @ParameterizedTest
        @MethodSource("validConfigurations")
        void shouldCreateFilterWithValidAndDeprecatedConfig(final JsonValue config) throws Exception {
            Name test = Name.of("test");
            HeapImpl heap = new HeapImpl(test);
            heap.put("HeaderCertificateRetriever", certificateResolver);
            heap.put("TransportCertValidator", transportCertValidator);
            Heaplet heaplet = new Heaplet();
            assertThat(heaplet.create(test, config, heap)).isNotNull();
        }
    }

    private static Context attrContextWithApiClient(ApiClient apiClient) {
        Context transactionIdContext = new TransactionIdContext(new RootContext(), new TransactionId("1234"));
        AttributesContext attributesContext = new AttributesContext(transactionIdContext);
        attributesContext.getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);
        return attributesContext;
    }

    private static void assertErrorResponse(Response response,
                                            String expectedErrorMessage,
                                            TestSuccessResponseHandler responseHandler) throws IOException {
        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getEntity().getJson().toString())
                .isEqualTo(json(object(field("error_description", expectedErrorMessage))).toString());
        assertThat(responseHandler.hasBeenInteractedWith()).isFalse();
    }
}