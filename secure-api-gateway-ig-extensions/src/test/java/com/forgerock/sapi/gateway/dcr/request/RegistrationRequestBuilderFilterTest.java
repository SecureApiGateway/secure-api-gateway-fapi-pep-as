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
package com.forgerock.sapi.gateway.dcr.request;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;
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
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.fapi.dcr.RegistrationException;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.RegistrationRequestFactory;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

class RegistrationRequestBuilderFilterTest {


    private final String REGISTRATION_REQUEST_JWT_STRING = CryptoUtils.createEncodedJwtString(Map.of(), JWSAlgorithm.PS256);

    private RegistrationRequestBuilderFilter filter;
    private final RegistrationRequestEntitySupplier reqRequestSupplier = new RegistrationRequestEntitySupplier();
    private static final JwtDecoder jwtDecoder = new JwtDecoder();
    private final RegistrationRequestFactory registrationRequestFactory = mock(RegistrationRequestFactory.class);

    // FIXME - use real responseFactory and assert that the correct error response is returned
    private final ResponseFactory responseFactory = mock(ResponseFactory.class);
    private final Handler handler = mock(Handler.class);

    @BeforeEach
    void setUp() {
        when(handler.handle(any(Context.class), any(Request.class))).thenReturn(newResultPromise(new Response(Status.OK)));
        filter = new RegistrationRequestBuilderFilter(registrationRequestFactory, reqRequestSupplier,
                                                      jwtDecoder, responseFactory);
    }

    @AfterEach
    void tearDown() {
        reset(registrationRequestFactory, responseFactory, handler);
    }

    @Test
    void shouldAddRegistrationRequestToContext() throws InterruptedException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        request.setMethod("POST");
        request.setEntity(REGISTRATION_REQUEST_JWT_STRING);

        final ArgumentCaptor<SignedJwt> captor = ArgumentCaptor.forClass(SignedJwt.class);
        final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
        when(registrationRequestFactory.createRegistrationRequest(captor.capture()))
                .thenReturn(newResultPromise(registrationRequest));

        // When
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        // Then
        Response response = promise.getOrThrow();
        assertThat(captor.getValue().build()).isEqualTo(REGISTRATION_REQUEST_JWT_STRING);

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        RegistrationRequest actualRegistrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(actualRegistrationRequest).isSameAs(registrationRequest);
    }

    @Test
    void shouldFailIfRegistrationRequestIsNotAJwt() throws Exception {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        request.setMethod("POST");
        request.setEntity("This is not a JWT");

        // When
        when(responseFactory.getResponse(any(List.class), eq(Status.BAD_REQUEST), any(Map.class))).thenReturn(new Response(Status.BAD_REQUEST));
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        // Then
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(context.getAttributes().get("registrationRequest")).isNull();
        verify(handler, never()).handle(context, request);
    }

    @Test
    void shouldReturnAnErrorIfRegistrationRequestFactoryReturnsAnException() throws Exception {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        request.setMethod("POST");
        request.setEntity(REGISTRATION_REQUEST_JWT_STRING);

        final ArgumentCaptor<SignedJwt> captor = ArgumentCaptor.forClass(SignedJwt.class);
        final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
        when(registrationRequestFactory.createRegistrationRequest(captor.capture()))
                .thenReturn(newExceptionPromise(new RegistrationException(RegistrationException.ErrorCode.INVALID_CLIENT_METADATA, "Invalid client metadata")));
        when(responseFactory.getResponse(any(List.class), eq(Status.BAD_REQUEST), any(Map.class))).thenReturn(new Response(Status.BAD_REQUEST));

        // When
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        // Then
        Response response = promise.getOrThrow();
        assertThat(captor.getValue().build()).isEqualTo(REGISTRATION_REQUEST_JWT_STRING);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(context.getAttributes().get("registrationRequest")).isNull();
        verify(handler, never()).handle(context, request);
    }


}