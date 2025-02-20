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
package com.forgerock.sapi.gateway.dcr.filter;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URISyntaxException;

import org.forgerock.http.Filter;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class AuthorizeResponsePathFetchApiClientFilterTest extends BaseResponsePathFetchApiClientFilterTest {


    @Override
    protected Filter createFilter() {
        final HeapImpl heap = new HeapImpl(Name.of("heap"));
        heap.put("apiClientService", apiClientService);
        final JsonValue config = json(object(field("apiClientService", "apiClientService")));
        try {
            return (ResponsePathFetchApiClientFilter) new AuthorizeResponseFetchApiClientFilterHeaplet().create(Name.of("test"), config, heap);
        } catch (HeapException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Request createRequest() {
        final Request request = new Request();
        try {
            request.setUri("/authorize?client_id=" + CLIENT_ID);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return request;
    }

    @Override
    protected Response createValidUpstreamResponse() {
        // /authorize response is a redirect
        return new Response(Status.FOUND);
    }

    @Test
    void returnsErrorResponseWhenClientIdParamNotFound() throws Exception {
        returnsErrorResponseWhenClientIdParamNotFound(new Request().setUri("/authorize"), createValidUpstreamResponse());
    }

    @Nested
    public class HeapletTests {
        @Test
        void failsToConstructIfApiClientServiceIsMissing() {
            final HeapException heapException = assertThrows(HeapException.class, () -> new AuthorizeResponseFetchApiClientFilterHeaplet().create(Name.of("test"),
                    json(object()), new HeapImpl(Name.of("heap"))), "Invalid object declaration");
            assertEquals(heapException.getCause().getMessage(), "/apiClientService: Expecting a value");
        }

        @Test
        void successfullyCreatesFilterWithRequiredConfigOnly() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("IdmApiClientService", apiClientService);

            final JsonValue config = json(object(field("apiClientService", "IdmApiClientService")));
            final ResponsePathFetchApiClientFilter filter = (ResponsePathFetchApiClientFilter) new AuthorizeResponseFetchApiClientFilterHeaplet().create(Name.of("test"), config, heap);

            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(filter);
        }
    }
}