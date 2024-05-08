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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.Filter;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Heaplet;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Pair;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.ApiClientTest;
import com.forgerock.sapi.gateway.jwks.ApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.mocks.MockJwkSetService;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilter.ParEndpointTransportCertValidationFilterHeaplet;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilter.TokenEndpointTransportCertValidationFilterHeaplet;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jose.JWSAlgorithm;

public class ResponsePathTransportCertValidationFilterTest {

    private static final String testClientId = "client-id-1234";

    private static ApiClient testApiClient;

    @BeforeAll
    public static void beforeAll() {
        try {
            testApiClient = ApiClientTest.createApiClientWithJwksUri(new URI("http://localhost/jwks"));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Nested
    class TransportCertValidationTests {

        private ResponsePathTransportCertValidationFilter certMandatoryTransportFilter;

        private TrustedDirectoryService mockTrustedDirectoryService;

        private ApiClientJwkSetService mockApiClientJwkSetService;

        private CertificateRetriever mockCertificateRetriever;

        private TransportCertValidator mockTransportCertValidator;

        private final TrustedDirectoryOpenBankingTest testTrustedDirectory = new TrustedDirectoryOpenBankingTest();

        @BeforeEach
        public void createValidFilter() {
            mockTrustedDirectoryService = mock(TrustedDirectoryService.class);
            mockApiClientJwkSetService = mock(ApiClientJwkSetService.class);

            // Default resolver behavior is to throw an exception
            mockCertificateRetriever = mock(CertificateRetriever.class, invocationOnMock -> {
                throw new CertificateException("invalid cert");
            });
            mockTransportCertValidator = mock(TransportCertValidator.class);

            certMandatoryTransportFilter = new ResponsePathTransportCertValidationFilter(mockTrustedDirectoryService,
                    mockApiClientJwkSetService, mockCertificateRetriever, mockTransportCertValidator, true);
        }

        @Test
        void failsWhenCertNotFoundAndCertIsMandatory() throws Exception {
            final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), handler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);

            validateResponseIsUnauthorised(response, "invalid cert");
            assertFalse(handler.hasBeenInteractedWith(), "next handler must not be reached");
        }

        @Test
        void skipsValidationWhenCertNotFoundAndCertNotMandatory() throws Exception {
            final TestSuccessResponseHandler handler = new TestSuccessResponseHandler();
            ResponsePathTransportCertValidationFilter filter = new ResponsePathTransportCertValidationFilter(
                    mockTrustedDirectoryService, mockApiClientJwkSetService, mockCertificateRetriever,
                    mockTransportCertValidator, false);

            doReturn(false).when(mockCertificateRetriever).certificateExists(any(), any());

            final Promise<Response, NeverThrowsException> responsePromise = filter.filter(createContext(), new Request(), handler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);

            assertEquals(Status.OK, response.getStatus());
            assertTrue(handler.hasBeenInteractedWith(), "next handler must have been called");
        }

        @Test
        void errorResponseFromNextHandlerIsPassedOn() throws Exception {
            // next handler in chain returns forbidden response
            final TestHandler nextHandler = new TestHandler(Handlers.forbiddenHandler());
            mockCertificateResolverValidCert();
            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.FORBIDDEN, response.getStatus());
        }

        @Test
        void failsWhenResponseJsonIOException() throws Exception {
            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                response.close(); // Close the response stream, causes end-of-input IOException
                return Promises.newResultPromise(response);
            });

            mockCertificateResolverValidCert();

            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenClientIdNotInResponse() throws Exception {
            final TestHandler nextHandler = new TestHandler((ctxt, request) -> {
                final Response response = new Response(Status.OK);
                // AM response missing access_token field
                final JsonValue jsonResponseMissingAccessTokenField = json(object(field("refresh_token", "addff")));
                response.setEntity(jsonResponseMissingAccessTokenField);
                return Promises.newResultPromise(response);
            });

            mockCertificateResolverValidCert();

            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenApiClientCouldNotBeFound() throws Exception {
            final TestHandler nextHandler = createHandlerWithValidResponse();

            mockCertificateResolverValidCert();

            final AttributesContext emptyContext = new AttributesContext(new RootContext());
            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(emptyContext, new Request(), nextHandler);

            final ExecutionException executionException = assertThrows(ExecutionException.class, () -> responsePromise.get(1, TimeUnit.MILLISECONDS));
            assertEquals("Required attribute: \"apiClient\" not found in context", executionException.getCause().getMessage());
        }

        @Test
        void failsWhenTrustedDirectoryConfigCouldNotBeFound() throws Exception {
            final TestHandler nextHandler = createHandlerWithValidResponse();

            mockCertificateResolverValidCert();

            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenApiClientJwksCouldNotBeFound() throws Exception {
            final TestHandler nextHandler = createHandlerWithValidResponse();

            mockCertificateResolverValidCert();
            mockTrustedDirectoryServiceReturndTestTrustedDirectory();

            doReturn(Promises.newExceptionPromise(new FailedToLoadJWKException("boom"))).when(mockApiClientJwkSetService).getJwkSet(eq(testApiClient), eq(testTrustedDirectory));

            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        }

        @Test
        void failsWhenTransportCertValidationFails()  throws Exception {
            final TestHandler nextHandler = createHandlerWithValidResponse();

            final X509Certificate clientCert = mock(X509Certificate.class);
            doReturn(clientCert).when(mockCertificateRetriever).retrieveCertificate(any(), any());
            mockTrustedDirectoryServiceReturndTestTrustedDirectory();

            final JWKSet clientJwks = new JWKSet();
            doReturn(Promises.newResultPromise(clientJwks)).when(mockApiClientJwkSetService).getJwkSet(eq(testApiClient), eq(testTrustedDirectory));
            doThrow(new CertificateException("Cert has expired")).when(mockTransportCertValidator).validate(eq(clientCert), eq(clientJwks));

            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            validateResponseIsUnauthorised(response, "Cert has expired");
        }

        @Test
        void succeedsWhenCertIsValid() throws Exception {
            final TestHandler nextHandler = createHandlerWithValidResponse();

            mockCertificateResolverValidCert();
            mockTrustedDirectoryServiceReturndTestTrustedDirectory();

            final JWKSet clientJwks = new JWKSet();
            doReturn(Promises.newResultPromise(clientJwks)).when(mockApiClientJwkSetService).getJwkSet(eq(testApiClient), eq(testTrustedDirectory));

            final Promise<Response, NeverThrowsException> responsePromise = certMandatoryTransportFilter.filter(createContext(), new Request(), nextHandler);
            final Response response = responsePromise.getOrThrow(1, TimeUnit.MILLISECONDS);

            assertEquals(Status.OK, response.getStatus());
            assertTrue(nextHandler.hasBeenInteractedWith());
        }

        private X509Certificate mockCertificateResolverValidCert() throws Exception {
            final X509Certificate mockCert = mock(X509Certificate.class);
            doReturn(mockCert).when(mockCertificateRetriever).retrieveCertificate(any(), any());
            return mockCert;
        }

        private void mockTrustedDirectoryServiceReturndTestTrustedDirectory() {
            doReturn(testTrustedDirectory).when(mockTrustedDirectoryService).getTrustedDirectoryConfiguration(eq(testApiClient));
        }

        private void validateResponseIsUnauthorised(Response response, String expectedErrorMsg) {
            assertEquals(Status.UNAUTHORIZED, response.getStatus());
            try {
                final JsonValue jsonResponse = json(response.getEntity().getJson());
                assertEquals(expectedErrorMsg, jsonResponse.get("error_description").asString());
                assertEquals("invalid_client", jsonResponse.get("error").asString());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private AttributesContext createContext() {
        final AttributesContext attributesContext = new AttributesContext(new RootContext("root"));
        attributesContext.getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, testApiClient);
        return attributesContext;
    }

    @Nested
    class HeapletTests {

        @ParameterizedTest
        @ValueSource(classes = {
                TokenEndpointTransportCertValidationFilterHeaplet.class,
                ParEndpointTransportCertValidationFilterHeaplet.class
        })
        public void testCertIsValidated(Class<? extends Heaplet> heapletClass) throws Exception {
            final Pair<X509Certificate, JWKSet> certAndJwks = CryptoUtils.generateTestTransportCertAndJwks("tls");
            final X509Certificate clientCert = certAndJwks.getFirst();
            final JWKSet clientJwks = certAndJwks.getSecond();
            final String certHeader = "ssl-client-cert";

            final Heaplet heaplet = heapletClass.getDeclaredConstructor().newInstance();
            final HeapImpl heap = new HeapImpl(Name.of("heap"));

            heap.put("trustedDirectoryService", (TrustedDirectoryService) issuer -> new TrustedDirectoryOpenBankingTest());
            heap.put("jwkSetService", new MockJwkSetService(Map.of(testApiClient.getJwksUri(), clientJwks)));
            heap.put("transportCertValidator", new DefaultTransportCertValidator());
            heap.put("headerCertificateRetriever", new HeaderCertificateRetriever(certHeader));

            final JsonValue config = json(object(field("trustedDirectoryService", "trustedDirectoryService"),
                                                 field("jwkSetService", "jwkSetService"),
                                                 field("transportCertValidator", "transportCertValidator"),
                                                 field("certificateRetriever", "headerCertificateRetriever")));
            final Filter filter = (Filter) heaplet.create(Name.of("test"), config, heap);

            final TestHandler nextHandler = createHandlerWithValidResponse();
            final Request request = HeaderCertificateRetrieverTest.createRequestWithCertHeader(clientCert, certHeader);

            final Promise<Response, NeverThrowsException> responsePromise = filter.filter(createContext(), request, nextHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);

            assertEquals(Status.OK, response.getStatus());
            assertTrue(nextHandler.hasBeenInteractedWith());
        }

    }

    private static String createAccessToken(Map<String, Object> claims) {
        return CryptoUtils.createEncodedJwtString(claims, JWSAlgorithm.PS256);
    }

    private TestHandler createHandlerWithValidResponse() {
        return new TestHandler((ctxt, request) -> Promises.newResultPromise(createResponseWithAccessToken(testClientId)));
    }

    public static Response createResponseWithAccessToken(String clientId) {
        final Response response = new Response(Status.OK);
        final JsonValue jsonResponse = json(object(field("access_token", createAccessToken(Map.of("aud", clientId)))));
        response.setEntity(jsonResponse);
        return response;
    }
}