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

import static com.forgerock.sapi.gateway.util.CryptoUtils.convertToPem;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.forgerock.json.JsonValue.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.Pair;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter;
import com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter.Heaplet;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class TransportCertValidationFilterTest {

    public static final String CERTIFICATE_HEADER_NAME = "ssl-client-cert";
    /**
     * TEST_TLS_CERT in URL encoded form, as provided by nginx
     */
    private static String TEST_TLS_CERT;
    /**
     * JWKSet containing TEST_TLS_CERT plus others
     */
    private static JWKSet TEST_JWKS;
    private final HeaderCertificateRetriever certificateResolver = new HeaderCertificateRetriever(CERTIFICATE_HEADER_NAME);
    private final DefaultTransportCertValidator certValidator = new DefaultTransportCertValidator("tls");

    @BeforeAll
    public static void beforeAll() throws Exception {
        final Pair<X509Certificate, JWKSet> testTransportCertAndJwks = CryptoUtils.generateTestTransportCertAndJwks("tls");
        TEST_TLS_CERT = URLEncoder.encode(convertToPem(testTransportCertAndJwks.getFirst()), Charset.defaultCharset());
        TEST_JWKS = testTransportCertAndJwks.getSecond();
    }

    @Test
    public void testValidCert() throws Exception {
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(certificateResolver, certValidator);
        testValidCert(transportCertValidationFilter);
    }

    private static void testValidCert(TransportCertValidationFilter transportCertValidationFilter) throws ExecutionException, TimeoutException, InterruptedException {
        final Context context = createContextWithJwksAttribute(TEST_JWKS);
        final Request request = createRequestWithCertHeader(CERTIFICATE_HEADER_NAME, TEST_TLS_CERT);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(context, request, responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(200, response.getStatus().getCode(), "HTTP Response Code");
        assertTrue(responseHandler.hasBeenInteractedWith(), "ResponseHandler must be called");
    }

    @Test
    public void failureResponseIfCertHeaderDoesNotExist() throws Exception {
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(certificateResolver, certValidator);
        final Context context = createContextWithJwksAttribute(TEST_JWKS);
        final Request request = new Request();

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(context, request, responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        verifyErrorResponse(response, "client tls certificate must be provided as a valid x509 certificate",
                            responseHandler);
    }

    @Test
    public void failureResponseIfCertHeaderValueCorrupted() throws Exception {
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(certificateResolver, certValidator);
        final Context context = createContextWithJwksAttribute(TEST_JWKS);
        final Request request = createRequestWithCertHeader(CERTIFICATE_HEADER_NAME, "badly formed cert...");

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(context, request, responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        verifyErrorResponse(response, "client tls certificate must be provided as a valid x509 certificate",
                            responseHandler);
    }

    @Test
    public void failureResponseIfApiClientJwksAttributeNotSet() {
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(certificateResolver, certValidator);
        final Context context = new AttributesContext(new RootContext());
        final Request request = createRequestWithCertHeader(CERTIFICATE_HEADER_NAME, TEST_TLS_CERT);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> transportCertValidationFilter.filter(context, request, responseHandler));
        assertEquals("Required attribute: \"apiClientJwkSet\" not found in context", exception.getMessage());
    }

    @Test
    public void failureResponseWhenCertNotInJwks() throws Exception {
        final TransportCertValidationFilter transportCertValidationFilter = new TransportCertValidationFilter(certificateResolver, certValidator);
        final Context context = createContextWithJwksAttribute(TEST_JWKS);
        final String certNotInJwks = URLEncoder.encode(convertToPem(generateX509Cert(generateRsaKeyPair(), "CN=test")), Charset.defaultCharset());
        final Request request = createRequestWithCertHeader(CERTIFICATE_HEADER_NAME, certNotInJwks);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = transportCertValidationFilter.filter(context, request, responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        verifyErrorResponse(response, "client tls certificate not found in JWKS for software statement", responseHandler);
    }

    @Nested
    public class HeapletTests {
        @Test
        void failToConstructIfCertValidatorIsMissing() {
            final Name test = Name.of("test");
            final JsonValueException heapException = assertThrows(JsonValueException.class,
                    () -> new Heaplet().create(test, json(object()), new HeapImpl(test)));
            assertEquals("/clientTlsCertHeader: Expecting a value", heapException.getMessage());
        }

        @Test
        void failToConstructIfCertHeaderNameIsMissing() {
            final Name test = Name.of("test");
            final JsonValueException heapException = assertThrows(JsonValueException.class,
                    () -> new Heaplet().create(test, json(object(field("clientTlsCertHeader", "blah"))), new HeapImpl(test)));
            assertEquals("/transportCertValidator: Expecting a value", heapException.getMessage());
        }

        @Test
        void successfullyCreatesFilterWithCertificateRetriever() throws Exception {
            final Name test = Name.of("test");
            final HeapImpl heap = new HeapImpl(test);
            heap.put("HeaderCertificateRetriever", new HeaderCertificateRetriever(CERTIFICATE_HEADER_NAME));
            heap.put("TransportCertValidator", certValidator);
            final JsonValue config = json(object(field("certificateRetriever", "HeaderCertificateRetriever"),
                                                 field("transportCertValidator", "TransportCertValidator")));
            final TransportCertValidationFilter filter = (TransportCertValidationFilter) new Heaplet().create(test, config, heap);
            testValidCert(filter);
        }

        @Test
        void successfullyCreatesFilterWithDeprecatedConfig() throws Exception {
            final Name test = Name.of("test");
            final HeapImpl heap = new HeapImpl(test);
            heap.put("TransportCertValidator", certValidator);
            final JsonValue config = json(object(field("clientTlsCertHeader", CERTIFICATE_HEADER_NAME),
                                                 field("transportCertValidator", "TransportCertValidator")));
            final TransportCertValidationFilter filter = (TransportCertValidationFilter) new Heaplet().create(test, config, heap);
            testValidCert(filter);
        }
    }

    private static Request createRequestWithCertHeader(String certificateHeaderName, String certValue) {
        final Request request = new Request().setMethod("GET");
        request.addHeaders(new GenericHeader(certificateHeaderName, certValue));
        return request;
    }

    private static Context createContextWithJwksAttribute(JWKSet jwkSet) {
        final Context context = new AttributesContext(new TransactionIdContext(new RootContext(), new TransactionId("1234")));
        addJwkSetToAttributesContext(context, jwkSet);
        return context;
    }

    private static void addJwkSetToAttributesContext(Context context, JWKSet jwkSet) {
        context.asContext(AttributesContext.class).getAttributes().put(FetchApiClientJwksFilter.API_CLIENT_JWKS_ATTR_KEY, jwkSet);
    }

    private static void verifyErrorResponse(Response response, String expectedErrorMessage, TestSuccessResponseHandler responseHandler) throws IOException {
        assertEquals(400, response.getStatus().getCode(), "HTTP Response Code");
        assertEquals(json(object(field("error_description", expectedErrorMessage))).toString(), response.getEntity().getJson().toString());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not be called");
    }
}