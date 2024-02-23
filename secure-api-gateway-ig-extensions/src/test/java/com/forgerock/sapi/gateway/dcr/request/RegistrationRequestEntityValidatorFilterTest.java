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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

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

import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequestFactory;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatementTestFactory;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;

class RegistrationRequestEntityValidatorFilterTest {

    private RegistrationRequestEntityValidatorFilter filter;
    private final RegistrationRequestEntitySupplier reqRequestSupplier = mock(RegistrationRequestEntitySupplier.class);
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
        filter = new RegistrationRequestEntityValidatorFilter(reqRequestSupplier, registrationRequestBuilder,
                responseFactory);
    }

    @AfterEach
    void tearDown() {
        reset(reqRequestSupplier, responseFactory, handler);
    }

    @Test
    void successWithJwskBasedRequest()
            throws InterruptedException, DCRRegistrationRequestBuilderException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        request.setMethod("POST");

        Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        // When
        when(reqRequestSupplier.apply(context, request)).thenReturn(createRegRequestB64EncodeJwtWithJwksBasedSSA(ssaClaims));
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
        // When
        when(reqRequestSupplier.apply(context, request)).thenReturn(createRegRequestB64EncodedJwtWithJwksUriBasedSSA(ssaClaimsOverrides));
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

        // When
        when(reqRequestSupplier.apply(context, request)).thenReturn(createRegRequestB64EncodedJwtWithJwksUriBasedSSA(Map.of()));
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
}