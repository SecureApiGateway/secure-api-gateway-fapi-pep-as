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
package com.forgerock.sapi.gateway.fapi;

import static com.forgerock.sapi.gateway.fapi.FapiUtils.X_FAPI_INTERACTION_ID;

import java.util.Optional;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * This filter aims to allow requests to be traced using the x-fapi-interaction-id header value (if it is present).
 * <p>
 * Functionality provided:
 * <ul>
 *     <li>
 *         Sets the {@link org.forgerock.services.context.TransactionIdContext} to the x-fapi-interaction-id.
 *         This means that the X-ForgeRock-TransactionID header sent to the ForgeRock platform will be set to the same
 *         value as the x-fapi-interaction-id header, which allows requests to be traced in these systems by searching
 *         logs for the x-fapi-interaction-id header value.
 *     </li>
 *     <li>
 *         Adds the x-fapi-interaction-id to the {@link MDC}, this includes the value in all log messages produced
 *         when processing the request
 *     </li>
 * </ul>
 */
public class FapiInteractionIdTracingFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final Optional<String> optionalInteractionId = FapiUtils.getFapiInteractionId(request);
        if (optionalInteractionId.isPresent()) {
            // Add the x-fapi-interaction-id to the MDC context for logging purposes, ensure the previously set value is restored
            final String previousMdcFapiInteractionId = MDC.get(X_FAPI_INTERACTION_ID);
            final String interactionId = optionalInteractionId.get();
            MDC.put(X_FAPI_INTERACTION_ID, interactionId);
            try {
                logger.debug("Found x-fapi-interaction-id: {}, mapping to TransactionId", optionalInteractionId);
                return next.handle(new TransactionIdContext(context, new TransactionId(interactionId)), request)
                           .thenAlways(() -> removeFapiInteractionIdFromMdc(previousMdcFapiInteractionId));
            } finally {
                removeFapiInteractionIdFromMdc(previousMdcFapiInteractionId);
            }
        }
        return next.handle(context, request);
    }

    private void removeFapiInteractionIdFromMdc(String previousFapiInteractionId) {
        if (previousFapiInteractionId == null) {
            MDC.remove(X_FAPI_INTERACTION_ID);
        } else {
            MDC.put(X_FAPI_INTERACTION_ID, previousFapiInteractionId);
        }
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiInteractionIdTracingFilter();
        }
    }
}
