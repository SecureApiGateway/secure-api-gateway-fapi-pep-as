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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.filter.ResponsePathFetchApiClientFilter.createFilterWithRequestClientIdRetriever;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.function.Function;

import org.forgerock.http.protocol.Request;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;

/**
 * Heaplet for creating a {@link ResponsePathFetchApiClientFilter} that can be used when protecting an OAuth2.0 PAR
 * (pushed authorisation request endpoint), the filter is configured to retrieve the client_id from the request JWT
 * in the {@link Request}'s Form entity.
 * <p>
 * Mandatory config:
 * - apiClientService: reference to an {@link ApiClientService} implementation heap object to use to retrieve the {@link ApiClient}
 * <p>
 * Example config:
 * <pre>{@code
 * {
 *   "name": "ParResponseFetchApiClientFilter",
 *   "type": "ParResponseFetchApiClientFilter",
 *   "comment": "Add ApiClient data to the context attributes for the AS /par route",
 *   "config": {
 *     "apiClientService": "IdmApiClientService"
 *   }
 * }
 * }</pre>
 */
public class ParResponseFetchApiClientFilterHeaplet extends GenericHeaplet {

    private static final Logger LOGGER = LoggerFactory.getLogger(ParResponseFetchApiClientFilterHeaplet.class);

    /**
     * Helper function capable of retrieving the client_id parameter from the request JWT in the {@link Request}'s
     * Form entity.
     *
     * @return Promise<String, NeverThrowsException> which returns the client_id or null if it does not exist
     */
    static Function<Request, Promise<String, NeverThrowsException>> formRequestJwtClientIdRetriever() {
        return request -> request.getEntity().getFormAsync()
                .then(form -> {
                    final String requestJwt = form.getFirst("request");
                    if (requestJwt == null) {
                        LOGGER.debug("Failed to extract client_id from /par request, no request JWT param found");
                        return null;
                    }
                    else {
                        try {
                            final SignedJwt signedJwt = new JwtReconstruction().reconstructJwt(requestJwt, SignedJwt.class);
                            return signedJwt.getClaimsSet().getClaim("client_id", String.class);
                        } catch (RuntimeException e) {
                            LOGGER.warn("Failed to extract client_id from /par request due to exception", e);
                            return null;
                        }
                    }
                })
                .thenCatch(ioe -> {
                    LOGGER.warn("Failed to extract client_id from /par request due to exception", ioe);
                    return null;
                });
    }

    @Override
    public Object create() throws HeapException {
        final ApiClientService apiClientService = config.get("apiClientService")
                                                        .as(requiredHeapObject(heap, ApiClientService.class));
        return createFilterWithRequestClientIdRetriever(apiClientService, formRequestJwtClientIdRetriever());
    }
}
