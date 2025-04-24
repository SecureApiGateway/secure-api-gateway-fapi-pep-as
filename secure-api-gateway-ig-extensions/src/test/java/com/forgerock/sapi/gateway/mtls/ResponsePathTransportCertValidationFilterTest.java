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

import static com.forgerock.sapi.gateway.util.CryptoUtils.createRequestWithCertHeader;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.context.FapiContext;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Heaplet;
import org.forgerock.openig.heap.Name;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Options;
import org.forgerock.util.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilter.ParEndpointTransportCertValidationFilterHeaplet;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilter.TokenEndpointTransportCertValidationFilterHeaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jose.JWSAlgorithm;

@ExtendWith(MockitoExtension.class)
public class ResponsePathTransportCertValidationFilterTest {
    private static final String API_CLIENT_ID = "client-id-1234";

    // The transport cert JWK's keyUse, and related purpose
    private static final String TRANSPORT_CERT_KEY_USE = "tls";

    // It's easier to use a real JwkSetSecretStore
    private static JwkSetSecretStore jwkSetSecretStore;

    @Mock
    private ApiClient testApiClient;

    @Nested
    class TransportCertValidationTests {
        private ResponsePathTransportCertValidationFilter certMandatoryTransportFilter;
        @Mock
        private TransportCertValidator transportCertValidator;

        @BeforeAll
        public static void setUpSecrets() {
            jwkSetSecretStore = new JwkSetSecretStore(new JWKSet(), Options.defaultOptions());
        }

        @BeforeEach
        public void createValidFilter() {
            // Default resolver behavior is to throw an exception
            certMandatoryTransportFilter = new ResponsePathTransportCertValidationFilter(transportCertValidator,
                                                                                         true);
        }

        @Test
        void shouldFailWhenCertNotFoundAndCertIsMandatory() {
            // Given
            TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
            // When
            Response response =
                    certMandatoryTransportFilter.filter(fapiContext(null, testApiClient), new Request(), nextHandler)
                                                .getOrThrowIfInterrupted();
            // Then
            assertThatResponseIsUnauthorised(response, "client mtls certificate must be provided");
            // TODO: Fix to use mock handler
            assertFalse(nextHandler.hasBeenInteractedWith(), "next handler must not be reached");
        }

        @Test
        void shouldSkipValidationWhenCertNotFoundAndCertNotMandatory() {
            // Given
            TestSuccessResponseHandler nextHandler = new TestSuccessResponseHandler();
            ResponsePathTransportCertValidationFilter filter =
                    new ResponsePathTransportCertValidationFilter(transportCertValidator, false);
            // When
            Response response = filter.filter(fapiContext(null, testApiClient), new Request(), nextHandler)
                                      .getOrThrowIfInterrupted();
            // Then
            assertEquals(Status.OK, response.getStatus());
            assertTrue(nextHandler.hasBeenInteractedWith(), "next handler must have been called");
            verifyNoInteractions(transportCertValidator);
        }

        @Test
        void shouldPassOnErrorResponseFromNextHandler() {
            //  Given - next handler in chain returns forbidden response
            TestHandler nextHandler = new TestHandler(Handlers.forbiddenHandler());
            X509Certificate mockCert = mock(X509Certificate.class);
            FapiContext fapiContext = fapiContext(mockCert, testApiClient);
            // When
            Response response =
                    certMandatoryTransportFilter.filter(fapiContext, new Request(),
                                                        nextHandler)
                                                .getOrThrowIfInterrupted();
            // Then
            assertEquals(Status.FORBIDDEN, response.getStatus());
            verifyNoInteractions(transportCertValidator);
        }

        @Test
        void shouldFailWhenApiClientNotFound() throws IOException {
            // Given
            TestHandler nextHandler = createHandlerWithValidResponse();
            X509Certificate mockCert = mock(X509Certificate.class);
            FapiContext fapiContext = fapiContext(mockCert, null);
            // When/Then
            Response response = certMandatoryTransportFilter.filter(fapiContext, new Request(), nextHandler)
                                                            .getOrThrowIfInterrupted();
            assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED);
            final JsonValue json = json(response.getEntity().getJson());
            assertThat(json.get("error").asString()).isEqualTo("invalid_client");
            assertThat(json.get("error_description").asString()).isEqualTo("ApiClient not found");
            verifyNoInteractions(transportCertValidator);
        }

        @Test
        void shouldFailWhenApiClientJwksCouldNotBeFound() {
            // Given
            TestHandler nextHandler = createHandlerWithValidResponse();
            X509Certificate mockCert = mock(X509Certificate.class);
            FapiContext fapiContext = fapiContext(mockCert, testApiClient);
            when(testApiClient.getJwkSetSecretStore())
                    .thenReturn(newExceptionPromise(new FailedToLoadJWKException("Failed to load JWKS")));
            // When
            Response response = certMandatoryTransportFilter.filter(fapiContext, new Request(), nextHandler)
                                                            .getOrThrowIfInterrupted();
            // Then
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
            verifyNoInteractions(transportCertValidator);
        }

        @Test
        void shouldFailWhenTransportCertValidationFails() {
            // Given
            TestHandler nextHandler = createHandlerWithValidResponse();
            X509Certificate clientCert = mock(X509Certificate.class);
            when(testApiClient.getJwkSetSecretStore()).thenReturn(newResultPromise(jwkSetSecretStore));
            when(transportCertValidator.validate(eq(clientCert), eq(jwkSetSecretStore)))
                    .thenReturn(newExceptionPromise(new CertificateException("Cert has expired")));
            FapiContext fapiContext = fapiContext(clientCert, testApiClient);
            // When
            Response response =
                    certMandatoryTransportFilter.filter(fapiContext, new Request(), nextHandler)
                                                .getOrThrowIfInterrupted();
            // Then
            assertThatResponseIsUnauthorised(response, "Cert has expired");
        }

        @Test
        void shouldSucceedWhenCertIsValid() {
            // Given
            TestHandler nextHandler = createHandlerWithValidResponse();
            X509Certificate clientCert = mock(X509Certificate.class);
            when(testApiClient.getJwkSetSecretStore()).thenReturn(newResultPromise(jwkSetSecretStore));
            when(transportCertValidator.validate(eq(clientCert), eq(jwkSetSecretStore)))
                    .thenReturn(newResultPromise(null));
            FapiContext fapiContext = fapiContext(clientCert, testApiClient);
            // When
            Response response =
                    certMandatoryTransportFilter.filter(fapiContext, new Request(), nextHandler)
                                                .getOrThrowIfInterrupted();
            // Then
            assertEquals(Status.OK, response.getStatus());
            assertTrue(nextHandler.hasBeenInteractedWith());
            verify(transportCertValidator).validate(eq(clientCert), eq(jwkSetSecretStore));
        }

        private void assertThatResponseIsUnauthorised(Response response, String expectedErrorMsg) {
            assertEquals(Status.UNAUTHORIZED, response.getStatus());
            try {
                JsonValue jsonResponse = json(response.getEntity().getJson());
                assertEquals(expectedErrorMsg, jsonResponse.get("error_description").asString());
                assertEquals("invalid_client", jsonResponse.get("error").asString());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private FapiContext fapiContext(final X509Certificate certificate, final ApiClient apiClient) {
        AttributesContext attributesContext = new AttributesContext(new RootContext("root"));
        FapiContext fapiContext = new FapiContext(attributesContext);
        if (certificate != null) {
            fapiContext.setClientCertificates(certificate);
        }
        if (apiClient != null) {
            fapiContext.setApiClient(apiClient);
        }
        return fapiContext;
    }

    @Nested
    class HeapletTests {

        private static X509Certificate clientCert;

        @BeforeAll
        public static void setUpSecrets() throws Exception {
            Pair<X509Certificate, JWKSet> certAndJwks =
                    CryptoUtils.generateTestTransportCertAndJwks(TRANSPORT_CERT_KEY_USE);
            clientCert = certAndJwks.getFirst();
            JWKSet clientJwks = certAndJwks.getSecond();
            jwkSetSecretStore = new JwkSetSecretStore(clientJwks, Options.defaultOptions());
        }

        @ParameterizedTest
        @ValueSource(classes = {
                TokenEndpointTransportCertValidationFilterHeaplet.class,
                ParEndpointTransportCertValidationFilterHeaplet.class
        })
        public void testCertIsValidated(Class<? extends Heaplet> heapletClass) throws Exception {
            // Given
            when(testApiClient.getJwkSetSecretStore()).thenReturn(newResultPromise(jwkSetSecretStore));
            String certHeader = "ssl-client-cert";
            // ... and heap
            Heaplet heaplet = heapletClass.getDeclaredConstructor().newInstance();
            HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("transportCertValidator", new DefaultTransportCertValidator());
            // ... and ResponsePathTransportCertValidationFilter config
            JsonValue config = json(object(field("trustedDirectoryService", "trustedDirectoryService"),
                                           field("jwkSetService", "jwkSetService"),
                                           field("transportCertValidator", "transportCertValidator")));
            Filter filter = (Filter) heaplet.create(Name.of("test"), config, heap);
            TestHandler nextHandler = createHandlerWithValidResponse();
            Request request = createRequestWithCertHeader(clientCert, certHeader);
            // When
            Response response = filter.filter(fapiContext(clientCert, testApiClient), request, nextHandler)
                                      .getOrThrowIfInterrupted();
            // Then
            assertEquals(Status.OK, response.getStatus());
            assertTrue(nextHandler.hasBeenInteractedWith());
        }
    }

    private static String createAccessToken(Map<String, Object> claims) {
        return CryptoUtils.createEncodedJwtString(claims, JWSAlgorithm.PS256);
    }

    private TestHandler createHandlerWithValidResponse() {
        return new TestHandler((ctxt, request) ->
                                       newResultPromise(createResponseWithAccessToken(API_CLIENT_ID)));
    }

    public static Response createResponseWithAccessToken(String clientId) {
        Response response = new Response(Status.OK);
        JsonValue jsonResponse = json(object(field("access_token", createAccessToken(Map.of("aud", clientId)))));
        response.setEntity(jsonResponse);
        return response;
    }
}