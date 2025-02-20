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
package com.forgerock.sapi.gateway.consent;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.filter.jwt.JwtValidationContext;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.openam.SsoTokenContext;
import org.forgerock.openig.tools.session.SessionInfo;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.ReflectionUtils;

import com.forgerock.sapi.gateway.consent.ConsentRequestAccessAuthorisationFilter.ExceptionHandler;
import com.forgerock.sapi.gateway.consent.ConsentRequestAccessAuthorisationFilter.Heaplet;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class ConsentRequestAccessAuthorisationFilterTest {

    private static final String TEST_USER_ID = "test-user";
    private CapturingExceptionHandler exceptionHandler;
    private ConsentRequestAccessAuthorisationFilter filter;

    @BeforeEach
    void beforeEach() {
        exceptionHandler = new CapturingExceptionHandler();
        filter = new ConsentRequestAccessAuthorisationFilter(
                ConsentRequestAccessAuthorisationFilter.DEFAULT_CONSENT_REQUEST_USER_ID_CLAIM,
                ConsentRequestAccessAuthorisationFilter.DEFAULT_SSO_TOKEN_USER_ID_KEY,
                exceptionHandler);
    }


    /**
     * Wrap the default exception handler and capture all exceptions passed to it.
     * This allows us to assert on the exceptions in the tests
     */
    static class CapturingExceptionHandler implements ExceptionHandler {
        private final ExceptionHandler delegateExceptionHandler = ConsentRequestAccessAuthorisationFilter.createDefaultExceptionHandler();

        private final List<Exception> capturedExceptions = new CopyOnWriteArrayList<>();

        @Override
        public Response onException(Context context, Exception ex) {
            capturedExceptions.add(ex);
            return delegateExceptionHandler.onException(context, ex);
        }
    }

    private void verifyExceptionHandlerContainsSingleException(Class<?> expectedExceptionClass, String expectedExceptionMessage) {
        assertEquals(1, exceptionHandler.capturedExceptions.size());
        final Exception exception = exceptionHandler.capturedExceptions.get(0);
        assertEquals(expectedExceptionClass, exception.getClass());
        assertEquals(expectedExceptionMessage, exception.getMessage());
    }

    private static void verifyInternalServerErrorResponse(Promise<Response, NeverThrowsException> responsePromise) {
        try {
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.INTERNAL_SERVER_ERROR.getCode(), response.getStatus().getCode());
        } catch (ExecutionException | TimeoutException | InterruptedException e) {
            throw new RuntimeException("Unexpected exception occurred getting response", e);
        }
    }

    private static void verifyUnauthorisedResponse(Promise<Response, NeverThrowsException> responsePromise) {
        try {
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.UNAUTHORIZED.getCode(), response.getStatus().getCode());
        } catch (ExecutionException | TimeoutException | InterruptedException e) {
            throw new RuntimeException("Unexpected exception occurred getting response", e);
        }
    }

    private static void verifySuccessResponse(Promise<Response, NeverThrowsException> responsePromise, TestSuccessResponseHandler responseHandler) {
        try {
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.OK.getCode(), response.getStatus().getCode());
            assertEquals(1, responseHandler.getNumInteractions());
        } catch (ExecutionException | TimeoutException | InterruptedException e) {
            throw new RuntimeException("Unexpected exception occurred getting response", e);
        }
    }

    private static SsoTokenContext createSsoTokenContext(Context parent, String uid) {
        // SessionInfo.username is mapped to SsoTokenContext.info.uid
        final JsonValue rawSessionInfo = json(object(field("username", uid)));
        final SessionInfo sessionInfo = new SessionInfo("dummyToken", rawSessionInfo);
        // Create SsoTokenContext object using reflection
        return ReflectionUtils.findMethod(SsoTokenContext.class, "fromSessionInfo", Context.class, SessionInfo.class, String.class)
                              .map(method -> {
                                    try {
                                        method.setAccessible(true);
                                        return (SsoTokenContext) method.invoke(null, parent, sessionInfo, "loginEndpoint");
                                    } catch (IllegalAccessException | InvocationTargetException e) {
                                        throw new RuntimeException("Failed to create SsoTokenContext using reflection", e);
                                    }
                              })
                              .orElseThrow(() -> new IllegalStateException("Failed to create SsoTokenContext using reflection - unable to find fromSessionInfo method"));
    }

    private static JwtValidationContext createMockJwtValidationContext(String username) {
        final JwtValidationContext jwtValidationContext = mock(JwtValidationContext.class);
        final JwtClaimsSet claims = new JwtClaimsSet(username != null ? Map.of("username", username) : Map.of());
        when(jwtValidationContext.getClaims()).thenReturn(claims);
        return jwtValidationContext;
    }

    @Test
    void testAuthorisedUser() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = createSsoTokenContext(createMockJwtValidationContext(TEST_USER_ID), TEST_USER_ID);
        verifySuccessResponse(filter.filter(context, new Request(), responseHandler), responseHandler);
    }

    @Test
    void testUnauthorisedUser() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = createSsoTokenContext(createMockJwtValidationContext("SomeOtherUser"), TEST_USER_ID);
        verifyUnauthorisedResponse(filter.filter(context, new Request(), responseHandler));
    }

    @Test
    void testSsoTokenContextMissing() {
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(new RootContext(),
                                                                                      new Request(),
                                                                                      new TestSuccessResponseHandler());

        verifyInternalServerErrorResponse(responsePromise);
        verifyExceptionHandlerContainsSingleException(IllegalArgumentException.class,
                "No context of type org.forgerock.openig.openam.SsoTokenContext found.");
    }

    @Test
    void testJwtValidationContextMissing() {
        final RootContext rootContext = new RootContext("root");
        final SsoTokenContext ssoTokenContext = createSsoTokenContext(rootContext, "test-user");

        verifyInternalServerErrorResponse(filter.filter(ssoTokenContext, new Request(), new TestSuccessResponseHandler()));
        verifyExceptionHandlerContainsSingleException(IllegalArgumentException.class,
                "No context of type org.forgerock.openig.filter.jwt.JwtValidationContext found.");
    }

    @Test
    void testJwtValidationContextUsernameClaimMissing() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = createSsoTokenContext(createMockJwtValidationContext(null), TEST_USER_ID);
        verifyInternalServerErrorResponse(filter.filter(context, new Request(), responseHandler));
        verifyExceptionHandlerContainsSingleException(IllegalStateException.class,
                "consent_request JWT username claim is missing or not a string");
    }

    @Test
    void testSsoTokenContextUidClaimMissing() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = createSsoTokenContext(createMockJwtValidationContext(TEST_USER_ID), null);
        verifyInternalServerErrorResponse(filter.filter(context, new Request(), responseHandler));
        verifyExceptionHandlerContainsSingleException(IllegalStateException.class,
                "SsoTokenContext.uid is missing or not a string");
    }

    @Test
    void testFilterCreatedByHeaplet() throws Exception {
        final Heaplet heaplet = new Heaplet();
        final ConsentRequestAccessAuthorisationFilter filterCreatedByHeaplet =
                (ConsentRequestAccessAuthorisationFilter) heaplet.create(Name.of("heaplet"),
                        json(object()), new HeapImpl(Name.of("heap")));

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = createSsoTokenContext(createMockJwtValidationContext(TEST_USER_ID), TEST_USER_ID);
        verifySuccessResponse(filterCreatedByHeaplet.filter(context, new Request(), responseHandler), responseHandler);
    }
}