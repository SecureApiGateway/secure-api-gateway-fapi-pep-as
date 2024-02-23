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
package com.forgerock.sapi.gateway.jwks;

import static com.forgerock.sapi.gateway.dcr.models.ApiClientTest.createApiClientWithJwksUri;
import static com.forgerock.sapi.gateway.jwks.DefaultApiClientJwkSetServiceTest.createJwkSet;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClientTest;
import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter.Heaplet;
import com.forgerock.sapi.gateway.jwks.mocks.MockJwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilter;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class FetchApiClientJwksFilterTest {

    @Test
    void testFetchApiClientJwks() throws Exception {
        final JWKSet jwkSet = createJwkSet();
        final MockApiClientJwkSetService apiClientJwkSetService = new MockApiClientJwkSetService(jwkSet);
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(apiClientJwkSetService);

        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, ApiClientTest.createBuilderWithJwks().build());
        addTrustedDirectoryToContext(context, new TrustedDirectoryOpenBankingTest());
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
        assertEquals(Status.OK, response.getStatus());
        assertTrue(responseHandler.hasBeenInteractedWith());

        // Verify JWKS is available in the context
        assertEquals(jwkSet, FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context));
    }

    @Test
    void failsIfApiClientNotFound() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());

        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(new ReturnsExeptionsApiClientJwkSetService());

        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> filter.filter(context, new Request(), responseHandler));
        assertEquals("apiClient not found in request context", exception.getMessage());
    }

    @Test
    void failsIfTrustedDirectoryNotFound() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, ApiClientTest.createBuilderWithJwks().build());

        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(new ReturnsExeptionsApiClientJwkSetService());

        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> filter.filter(context, new Request(), responseHandler));
        assertEquals("trustedDirectory not found in request context", exception.getMessage());
    }

    @Test
    void failsIfApiClientJwksSetServiceThrowsException() throws ExecutionException, InterruptedException, TimeoutException {
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(new ReturnsExeptionsApiClientJwkSetService());

        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, ApiClientTest.createBuilderWithJwks().build());
        addTrustedDirectoryToContext(context, new TrustedDirectoryOpenBankingTest());
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);

        final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith()); // The filter must not have passed the request on to the next handler
    }

    @Nested
    class HeapletTests {

        @Test
        void failsToConstructWhenMissingJwksService() {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            final JsonValue config = json(object());
            final HeapException heapException = assertThrows(HeapException.class, () -> new Heaplet().create(Name.of("test"), config, heap));
            assertEquals("/jwkSetService: Expecting a value", heapException.getCause().getMessage());
        }

        @Test
        void successfullyCreatesFilter() throws Exception {
            final JWKSet jwkSet = createJwkSet();
            final URL jwksUri = new URL("https://directory.com/jwks/12345");
            final MockJwkSetService jwkSetService = new MockJwkSetService(Map.of(jwksUri, jwkSet));

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("JwkSetService", jwkSetService);
            final JsonValue config = json(object(field("jwkSetService", "JwkSetService")));

            final FetchApiClientJwksFilter filter = (FetchApiClientJwksFilter) new Heaplet().create(Name.of("test"), config, heap);

            final Context context = new AttributesContext(new RootContext());
            addApiClientToContext(context, createApiClientWithJwksUri(jwksUri.toURI()));
            addTrustedDirectoryToContext(context, new TrustedDirectoryOpenBankingTest());
            final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
            final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
            final Response response = responsePromise.get(1, TimeUnit.MILLISECONDS);
            assertEquals(Status.OK, response.getStatus());
            assertTrue(responseHandler.hasBeenInteractedWith());

            // Verify JWKS is available in the context
            assertEquals(jwkSet, FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context));
        }
    }

    private static final class MockApiClientJwkSetService implements ApiClientJwkSetService {

        private final JWKSet jwkSet;

        MockApiClientJwkSetService(JWKSet jwkSet) {
            this.jwkSet = jwkSet;
        }

        @Override
        public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(ApiClient apiClient, TrustedDirectory trustedDirectory) {
            return Promises.newResultPromise(jwkSet);
        }
    }

    private static final class ReturnsExeptionsApiClientJwkSetService implements ApiClientJwkSetService {
        @Override
        public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(ApiClient apiClient, TrustedDirectory trustedDirectory) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("failed to load JWK"));
        }
    }

    private void addApiClientToContext(Context context, ApiClient apiClient) {
        context.asContext(AttributesContext.class).getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);
    }

    private void addTrustedDirectoryToContext(Context context, TrustedDirectory trustedDirectory) {
        context.asContext(AttributesContext.class).getAttributes()
                .put(FetchTrustedDirectoryFilter.TRUSTED_DIRECTORY_ATTR_KEY, trustedDirectory);
    }


}
