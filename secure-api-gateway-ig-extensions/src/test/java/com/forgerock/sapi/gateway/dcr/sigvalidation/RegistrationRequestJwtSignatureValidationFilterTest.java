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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeNegotiator;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequestFactory;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;

class RegistrationRequestJwtSignatureValidationFilterTest {

    private static final String ERROR_DESCRIPTION = "Error Description";
    private Request request;
    private Handler handler = mock(Handler.class);
    private AttributesContext context;
    private RegistrationRequestJwtSignatureValidationFilter filter;
    private final RegistrationRequestJwtSignatureValidationService dcrRegistrationRequestSignatureValidator
            = mock(RegistrationRequestJwtSignatureValidationService.class);
    private final SoftwareStatementAssertionSignatureValidatorService ssaSignatureValidatorService
            = mock(SoftwareStatementAssertionSignatureValidatorService.class);

    private static ResponseFactory responseFactory;

    @BeforeAll
    static void setupAll(){
        final ContentTypeFormatterFactory contentTypeFormatterFactory = new ContentTypeFormatterFactory();
        final ContentTypeNegotiator contentTypeNegotiator =
                new ContentTypeNegotiator(contentTypeFormatterFactory.getSupportedContentTypes());
        responseFactory = new ResponseFactory(contentTypeNegotiator,
                contentTypeFormatterFactory);
    }


    @BeforeEach
    void setUp() {
        handler = mock(Handler.class);
        this.request = new Request().setMethod("POST");
        filter = new RegistrationRequestJwtSignatureValidationFilter(
                ssaSignatureValidatorService, dcrRegistrationRequestSignatureValidator, responseFactory);
        context = new AttributesContext(new RootContext());
    }

    @AfterEach
    void tearDown() {
        reset(handler, dcrRegistrationRequestSignatureValidator,
                ssaSignatureValidatorService);
    }

    private RegistrationRequest getRegRequestWithJwksSsa() throws DCRRegistrationRequestBuilderException {
        Map<String, Object> regRequestClaimOverrides = Map.of();
        Map<String, Object> ssaClaimOverrides = Map.of();
        return RegistrationRequestFactory.getRegRequestWithJwksSoftwareStatement(regRequestClaimOverrides,
                ssaClaimOverrides);
    }

    private RegistrationRequest getRegRequestWithJwksUriSsa() throws DCRRegistrationRequestBuilderException {
        Map<String, Object> regRequestClaimOverrides = Map.of();
        Map<String, Object> ssaClaimOverrides = Map.of();
        return RegistrationRequestFactory.getRegRequestWithJwksUriSoftwareStatement(regRequestClaimOverrides,
                ssaClaimOverrides);
    }

    @Test
    void filter_successSoftwareStatementWithJwskUri() throws Exception {
        // Given
        RegistrationRequest registrationRequest = getRegRequestWithJwksSsa();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(ssaSignatureValidatorService.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assert(response.getStatus()).isSuccessful();
        verify(handler, times(1)).handle(context, request);
    }

    @Test
    void filter_ResultContainsInvalidClientMetadataWhenNoContextAttribute() throws Exception {
        // Given
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(ssaSignatureValidatorService.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.getOrThrow();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(context, request);
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenSignatureIsInvalid() throws Exception{
        // Given
        RegistrationRequest registrationRequest = getRegRequestWithJwksSsa();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(ssaSignatureValidatorService.validateJwtSignature(any()))
                .thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, "invalid jwt signature")));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains(DCRErrorCode.INVALID_SOFTWARE_STATEMENT.getCode());
        verify(handler, never()).handle(context, request);
    }

    @Test
    void filter_ResponseIsInvalidSoftwareStatementWhenRTEValidatingSSA() throws Exception{
        // Given
        RegistrationRequest registrationRequest = getRegRequestWithJwksSsa();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(ssaSignatureValidatorService.validateJwtSignature(any()))
                .thenReturn(Promises.newRuntimeExceptionPromise(
                    new DCRSignatureValidationRuntimeException("Runtime exception validating SSA")));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenRegRequestSigInvalid() throws Exception {
        // Given
        RegistrationRequest registrationRequest = getRegRequestWithJwksSsa();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(ssaSignatureValidatorService.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any()))
                .thenReturn(Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, ERROR_DESCRIPTION)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).contains(ERROR_DESCRIPTION);
        verify(handler, never()).handle(null, request);
    }

    @Test
    void filter_ResponseIsInvalidClientMetadataWhenRTEValidatingRegRequestSig() throws Exception {
        // Given
        RegistrationRequest registrationRequest = getRegRequestWithJwksSsa();
        context.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        Promise<Response, NeverThrowsException> resultPromise = Response.newResponsePromise(new Response(Status.OK));
        when(handler.handle(any(), any())).thenReturn(resultPromise);
        when(ssaSignatureValidatorService.validateJwtSignature(any()))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        when(dcrRegistrationRequestSignatureValidator.validateJwtSignature(any()))
                .thenReturn(Promises.newRuntimeExceptionPromise(
                        new DCRSignatureValidationRuntimeException(ERROR_DESCRIPTION)));

        // When
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(null, request, handler);
        Response response = responsePromise.get();

        // Then
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        verify(handler, never()).handle(null, request);
    }
}