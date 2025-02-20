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
package com.forgerock.sapi.gateway.fapi;

import static com.forgerock.sapi.gateway.fapi.FapiUtils.X_FAPI_INTERACTION_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import com.forgerock.sapi.gateway.fapi.FapiInteractionIdTracingFilter.Heaplet;
import com.forgerock.sapi.gateway.util.TestHandlers;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;

class FapiInteractionIdTracingFilterTest {

    private final FapiInteractionIdTracingFilter filter;

    FapiInteractionIdTracingFilterTest() throws HeapException {
        filter = (FapiInteractionIdTracingFilter) new Heaplet().create();
    }

    private static String generateInteractionId() {
        return UUID.randomUUID().toString();
    }

    @Test
    void shouldNotCreateTransactionIdIfFapiInteractionIdMissing() {
        final Response expectedResponse = new Response(Status.OK);
        final TestHandler successResponseHandler = new TestHandler((ctxt, req) -> {
            assertFalse(ctxt.containsContext(TransactionIdContext.class), "No TransactionIdContext should be created");
            assertNull(MDC.get(X_FAPI_INTERACTION_ID), "x-fapi-interaction-id must not be set in the MDC");
            return Promises.newResultPromise(expectedResponse);
        });

        final Response response = TestHandlers.invokeFilter(filter, new Request(), successResponseHandler);
        assertEquals(expectedResponse, response);
    }

    @Test
    void shouldMapFapiInteractionIdOnToTransactionId() {
        final String interactionId = generateInteractionId();

        final Response expectedResponse = new Response(Status.OK);
        final TestHandler successResponseHandler = new TestHandler((ctxt, req) -> {
            assertTrue(ctxt.containsContext(TransactionIdContext.class), "TransactionIdContext must exist");
            assertEquals(interactionId, ctxt.asContext(TransactionIdContext.class).getTransactionId().getValue(),
                    "TransactionIdContext id value must match x-fapi-interaction-id header");
            assertEquals(interactionId, MDC.get(X_FAPI_INTERACTION_ID), "MDC.x-fapi-interaction-id must match the header");
            return Promises.newResultPromise(expectedResponse);
        });

        final Request request = new Request();
        request.addHeaders(new GenericHeader(X_FAPI_INTERACTION_ID, interactionId));
        final Response response = TestHandlers.invokeFilter(filter, request, successResponseHandler);
        assertEquals(expectedResponse, response);
    }

}