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
package com.forgerock.sapi.gateway.dcr.request;

import static com.forgerock.sapi.gateway.util.CryptoUtils.createEncodedJwtString;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequestFactory;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatementTestFactory;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;
import com.forgerock.sapi.gateway.util.ContextUtils;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class RegistrationRequestBuilderFilterTest {

    private RegistrationRequestBuilderFilter filter;
    private final RegistrationRequestEntitySupplier reqRequestSupplier = new RegistrationRequestEntitySupplier();
    private static RegistrationRequest.Builder registrationRequestBuilder ;
    private static final JwtDecoder jwtDecoder = new JwtDecoder();
    private final ResponseFactory responseFactory = mock(ResponseFactory.class);
    private final Handler handler = mock(Handler.class);

    @BeforeAll
    static void setupClass()  {
        TrustedDirectoryService trustedDirectoryService = TrustedDirectoryTestFactory.getTrustedDirectoryService();
        SoftwareStatement.Builder softwareStatementBuilder = new SoftwareStatement.Builder(trustedDirectoryService, jwtDecoder);
        registrationRequestBuilder = new RegistrationRequest.Builder(softwareStatementBuilder, jwtDecoder);
    }

    @BeforeEach
    void setUp() {
        when(handler.handle(any(Context.class), any(Request.class)))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        filter = new RegistrationRequestBuilderFilter(reqRequestSupplier, registrationRequestBuilder,
                responseFactory);
    }

    @AfterEach
    void tearDown() {
        reset(responseFactory, handler);
    }

    @Test
    void successWithJwskBasedRequest()
            throws InterruptedException, DCRRegistrationRequestBuilderException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        Request request = new Request();
        request.setMethod("POST");
        request.setEntity(createRegRequestB64EncodeJwtWithJwksBasedSSA(ssaClaims));

        // When
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        assertThat(promise).isNotNull();
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        RegistrationRequest registrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(registrationRequest).isNotNull();
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.hasJwksUri()).isFalse();
    }

    @Test
    void errorWhenUnrecognisedSSAIssuer_filter() throws InterruptedException, DCRRegistrationRequestBuilderException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        request.setMethod("POST");
        Map<String, Object> ssaClaimsOverrides = Map.of("iss", "invalid_issuer");
        request.setEntity(createRegRequestB64EncodedJwtWithJwksUriBasedSSA(ssaClaimsOverrides));

        // When
        when(responseFactory.getResponse(any(List.class), eq(Status.BAD_REQUEST), any(Map.class))).thenReturn(new Response(Status.BAD_REQUEST));
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        assertThat(promise).isNotNull();
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        RegistrationRequest registrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(registrationRequest).isNull();
        verify(handler, never()).handle(context, request);
    }

    private String createRegRequestB64EncodeJwtWithJwksBasedSSA(Map<String, Object> ssaClaimOverrides)
            throws DCRRegistrationRequestBuilderException {
        RegistrationRequest regReq =
                RegistrationRequestFactory.getRegRequestWithJwksSoftwareStatement(Map.of(), ssaClaimOverrides);
        return regReq.getB64EncodedJwtString();
    }

    @Test
    void successWithOBTestDirectoryRequest_filter() throws InterruptedException, DCRRegistrationRequestBuilderException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        request.setMethod("POST");
        request.setEntity(createRegRequestB64EncodedJwtWithJwksUriBasedSSA(Map.of()));

        // When
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        assertThat(promise).isNotNull();
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        RegistrationRequest registrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(registrationRequest).isNotNull();
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.hasJwksUri()).isTrue();
    }

    private String createRegRequestB64EncodedJwtWithJwksUriBasedSSA(Map<String, Object> ssaClaims)
            throws  DCRRegistrationRequestBuilderException {
        RegistrationRequest regRequest =
                RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement(Map.of(), ssaClaims);
        return  regRequest.getB64EncodedJwtString();
    }

    /**
     * Test which demonstrates the race condition that arises when sharing an instance of the builder across threads.
     * The number of threads used by the test is parameterized, the test will pass when a single thread is used, and
     * will fail when multiple are used. Running with a single thread is a sanity test to verify the test logic is sound.
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 16})
    void shouldSucceedWhenCalledConcurrently(int numThreads) throws InterruptedException, ExecutionException {
        final Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        final String ssaJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);

        Map<String, Object> baseClaims = Map.of("token_endpoint_auth_method", "private_key_jwt",
                                                "scope", "openid accounts payments",
                                                "response_types", List.of("code id_token"),
                                                "token_endpoint_auth_signing_alg", "PS256",
                                                "id_token_signed_response_alg", "PS256",
                                                "request_object_signing_alg", "PS256",
                                                "software_statement", ssaJwt);

        final int tasks = 256;
        final List<Callable<Void>> callables = new ArrayList<>(tasks);
        for (int i = 0; i < tasks; i++) {
            final Map<String, Object> taskClaims = new HashMap<>(baseClaims);
            // Add some uniqueness to the registration request JWT
            final List<String> redirectUris = List.of("https://google.co.uk/" + i);
            taskClaims.put("redirect_uris", redirectUris);
            final String issuer = "ACME Fintech" + i;
            taskClaims.put("iss", issuer);

            final String registrationRequestJwt = createEncodedJwtString(taskClaims, JWSAlgorithm.PS256);
            final AttributesContext context = new AttributesContext(new RootContext());
            final Request request = new Request();
            request.setMethod("POST");
            request.getEntity().setString(registrationRequestJwt);

            // Create a task which invokes the filter and verifies the registrationRequest contains the unique data for the particular task
            callables.add(() -> {
                final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
                responsePromise.getOrThrow();

                // Validate the RegistrationRequest created by the filter
                final RegistrationRequest registrationRequest = ContextUtils.getRequiredAttributeAsType(context, RegistrationRequest.REGISTRATION_REQUEST_KEY, RegistrationRequest.class);
                assertThat(registrationRequest.getRedirectUris()).isEqualTo(redirectUris.stream().map(URI::create).toList());
                assertThat(registrationRequest.getIssuer()).isEqualTo(issuer);
                return null;
            });
        }
        ExecutorService executorService = Executors.newFixedThreadPool(numThreads);
        try {
            final List<Future<Void>> futures = executorService.invokeAll(callables);
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            executorService.shutdown();
        }
    }
}