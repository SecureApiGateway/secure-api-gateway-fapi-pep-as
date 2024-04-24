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
package com.forgerock.sapi.gateway.metrics;

import java.util.Collections;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * Supplies context data to store in the RouteMetricsEvent.context field.
 * <p>
 * This data is optional, it allows routes to supply additional custom contextual information about a request.
 */
public interface MetricsContextSupplier {

    /**
     * Implementation which returns an empty context, this can be used for routes which do not have any context
     * information to report.
     */
    MetricsContextSupplier EMPTY_CONTEXT_SUPPLIER = (requestContext, request) -> Promises.newResultPromise(Collections.emptyMap());

    /**
     * Extract Metrics Context information for the given HTTP Request and Request Context.
     *
     * @param requestContext HTTP request's Context which may be used to extract metrics context information from
     * @param request        HTTP request which may be used to extract metrics context information from
     * @return Promise with a Map<String, Object> containing the metrics context information for this request.
     * NOTE: must be serializable to JSON using the {@link org.forgerock.http.util.Json#writeJson(Object)} method.
     * When there is no context information to report then an empty Map should be returned.
     */
    Promise<Map<String, Object>, NeverThrowsException> getMetricsContext(Context requestContext, Request request);

}
