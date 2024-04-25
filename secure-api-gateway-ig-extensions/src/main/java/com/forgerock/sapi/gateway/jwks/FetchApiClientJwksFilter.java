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

import static com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter.getApiClientFromContext;
import static com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilter.getTrustedDirectoryFromContext;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilter;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.util.ContextUtils;

/**
 * Filter which fetches a {@link JWKSet} containing the keys for an {@link ApiClient} that are registered with a
 * {@link TrustedDirectory}
 *
 * The ApiClient is looked up from the AttributesContext.
 *
 * To determine where to find the JWKSet for an ApiClient, the {@link TrustedDirectory} configuration is required.
 * This is also retrieved from the AttributesContext.
 *
 * Therefore, this filter must be installed after a filters which set these attributes, typically: {@link FetchApiClientFilter}
 * and {@link FetchTrustedDirectoryFilter}
 */
public class FetchApiClientJwksFilter implements Filter {

    /**
     * The key to use to get the JWKSet for the ApiClient from the AttributesContext
     */
    public static final String API_CLIENT_JWKS_ATTR_KEY = "apiClientJwkSet";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ApiClientJwkSetService apiClientJwkSetService;

    /**
     * Utility method to retrieve a {@link JWKSet} object from a Context, which belongs to the ApiClient.
     * This method can be used by other filters to retrieve the JWKSet installed into the attributes context by
     * this filter.
     *
     * @param context the context to retrieve the JWKSet from
     * @return the JWKSet from the context
     */
    public static JWKSet getApiClientJwkSetFromContext(Context context) {
        return ContextUtils.getRequiredAttributeAsType(context, API_CLIENT_JWKS_ATTR_KEY, JWKSet.class);
    }

    public FetchApiClientJwksFilter(ApiClientJwkSetService apiClientJwkSetService) {
        Reject.ifNull(apiClientJwkSetService, "apiClientJwkSetService must be provided");
        this.apiClientJwkSetService = apiClientJwkSetService;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final ApiClient apiClient = getApiClientFromContext(context);
        final TrustedDirectory trustedDirectory = getTrustedDirectoryFromContext(context);

        return apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory).thenAsync(jwkSet -> {
            logger.debug("Added jwks to context for apiClient");
            context.asContext(AttributesContext.class).getAttributes().put(API_CLIENT_JWKS_ATTR_KEY, jwkSet);
            return next.handle(context, request);
        }, ex -> {
            logger.error("Failed to load JWKS for apiClient: {} and trusted directory: {} due to exception",
                    apiClient, trustedDirectory, ex);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        }, rte -> {
            logger.error("Failed to load JWKS for apiClient: {} and trusted directory: {} due to exception",
                    apiClient, trustedDirectory, rte);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        });
    }

    /**
     * Heaplet responsible for constructing {@link FetchApiClientFilter} objects.
     *
     * Configuration:
     * - jwkSetService the name of the JwkSetService object on the heap to use to fetch remote JWKSets
     *
     * Example config:
     * {
     *      "comment": "Add the JWKS for the ApiClient to the context attributes",
     *      "name": "FetchApiClientJwksFilter",
     *      "type": "FetchApiClientJwksFilter",
     *      "config": {
     *          "jwkSetService": "OBJwkSetService"
     *       }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final JwkSetService jwkSetService = config.get("jwkSetService").as(requiredHeapObject(heap, JwkSetService.class));
            return new FetchApiClientJwksFilter(new DefaultApiClientJwkSetService(jwkSetService));
        }
    }
}
