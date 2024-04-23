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

import static com.forgerock.sapi.gateway.dcr.filter.ResponsePathFetchApiClientFilter.createFilterWithResponseClientIdRetriever;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.function.Function;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;


/**
 * Filter to fetch the {@link ApiClient} on the response path when protecting an OAuth2.0 token endpoint.
 * <p>
 * This filter wraps a {@link ResponsePathFetchApiClientFilter} that is configured to retrieve the client_id from the
 * response access_token JWT. The claim to retrieve the client_id from is configurable, defaulting to "aud".
 */
public class TokenEndpointResponseFetchApiClientFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    static final String DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM = "aud";

    /**
     * Name of the access_token JWT claim containing the OAuth 2 client_id
     */
    private final String accessTokenClientIdClaim;

    private final JwtReconstruction jwtReconstruction = new JwtReconstruction();

    /**
     * Filter to delegate to, that is configured with the {@link #accessTokenClientIdRetriever()} Function to retrieve
     * the client_id from the token endpoint response.
     */
    private final ResponsePathFetchApiClientFilter delegateFilter;

    public TokenEndpointResponseFetchApiClientFilter(ApiClientService apiClientService, String accessTokenClientIdClaim) {
        this.accessTokenClientIdClaim = Reject.checkNotBlank(accessTokenClientIdClaim, "accessTokenClientIdClaim must be provided");
        this.delegateFilter = createFilterWithResponseClientIdRetriever(apiClientService,
                                                                        accessTokenClientIdRetriever());
    }

    /**
     * Retrieves the client_id from a {@link Response}. The Response is expected to be a successful token endpoint
     * response, and contain a json payload with an access_token object which is a JWT.
     *
     * @return client_id retrieving from the access token.
     */
    private Function<Response, Promise<String, NeverThrowsException>> accessTokenClientIdRetriever() {
        return response -> response.getEntity()
                                   .getJsonAsync()
                                   .then(this::getClientIdFromJsonEntity,
                                         ioe -> {
                                             logger.warn("Failed to retrieve client_id from access_token due to being unable to retrieve json entity", ioe);
                                             return null;
                                         });
    }

    /**
     * Extracts the client_id from token endpoint response json.
     * This method expects the json to contain an "access_token" object that is a JWT, within the JWT the client_id is
     * expected to be contained in the configurable accessTokenClientIdClaim claim.
     *
     * @param jsonValue the raw token endpoint response json
     * @return the client_id
     */
    @VisibleForTesting
    String getClientIdFromJsonEntity(Object jsonValue) {
        final JsonValue json = JsonValue.json(jsonValue);
        final JsonValue accessToken = json.get("access_token");
        if (accessToken == null || accessToken.isNull()) {
            throw new IllegalStateException("Failed to get client_id: access_token is missing");
        }

        final SignedJwt accessTokenJwt = jwtReconstruction.reconstructJwt(accessToken.asString(), SignedJwt.class);
        final JsonValue clientId = accessTokenJwt.getClaimsSet().get(accessTokenClientIdClaim);
        if (clientId.isNull()) {
            throw new IllegalStateException("Failed to get client_id: access_token claims missing required '" + accessTokenClientIdClaim + "' claim");
        }
        return clientId.asString();
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        return delegateFilter.filter(context, request, handler);
    }

    /**
     * Heaplet responsible for creating {@link TokenEndpointResponseFetchApiClientFilter} objects.
     * <p>
     * Mandatory config:
     * <ul>
     *     <li>
     *      apiClientService: reference to an {@link ApiClientService} implementation heap object to use to retrieve the {@link ApiClient}
     *     </li>
     * </ul>
     * <p>
     * Optional config:
     * <ul>
     *     <li>
     *      accessTokenClientIdClaim: string, the claim to retrieve the client_id from, defaults to "aud"
     *     </li>
     * </ul>
     *
     *
     * Example config:
     * <pre>{@code
     * {
     *   "name": "TokenEndpointResponseFetchApiClientFilter",
     *   "type": "TokenEndpointResponseFetchApiClientFilter",
     *   "comment": "Add ApiClient data to the context attributes for the AS token endpoint route",
     *   "config": {
     *     "apiClientService": "IdmApiClientService"
     *   }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final ApiClientService apiClientService = config.get("apiClientService")
                                                            .as(requiredHeapObject(heap, ApiClientService.class));

            final String accessTokenClientIdClaim =  config.get("accessTokenClientIdClaim")
                                                           .defaultTo(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM)
                                                           .asString();

            return new TokenEndpointResponseFetchApiClientFilter(apiClientService, accessTokenClientIdClaim);
        }
    }
}
