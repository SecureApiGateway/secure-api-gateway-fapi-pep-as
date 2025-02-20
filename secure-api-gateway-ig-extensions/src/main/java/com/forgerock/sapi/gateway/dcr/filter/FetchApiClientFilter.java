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
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.oauth2.OAuth2Context;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.service.ApiClientService;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException.ErrorCode;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.ResultHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.util.ContextUtils;

/**
 * Fetches {@link ApiClient} data from IDM using the client_id identified from the access_token provided with this request.
 * The {@link ApiClient} retrieved is then made accessible via the AttributesContext as key: "apiClient", other filters
 * in the chain can then access this data using the context.
 * <p>
 * This filter relies on the OAuth2Context being present, therefore it must be installed after a filter which adds this
 * context, such as OAuth2ResourceServerFilter.
 */
public class FetchApiClientFilter implements Filter {

    /**
     * The key to use to get the ApiClient from the AttributesContext
     */
    public static final String API_CLIENT_ATTR_KEY = "apiClient";

    /**
     * The default claim to use to extract the client_id from the access_token
     */
    private static final String DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM = "aud";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The claim in the access_token where the client_id can be found, see DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM
     */
    private final String accessTokenClientIdClaim;

    /**
     * Service which can retrieve ApiClient data
     */
    private final ApiClientService apiClientService;

    /**
     * Utility method to retrieve an ApiClient object from a Context.
     * This method can be used by other filters to retrieve the ApiClient installed into the attributes context by
     * this filter.
     *
     * @param context the context to retrieve the ApiClient from
     * @return the ApiClient from the context
     */
    public static ApiClient getApiClientFromContext(Context context) {
        return ContextUtils.getRequiredAttributeAsType(context, API_CLIENT_ATTR_KEY, ApiClient.class);
    }

    /**
     * Creates a ResultHandler responsible for adding the ApiClient result to the Attributes Context.
     * <p>
     * A new handler needs to be created per result.
     *
     * @param context Context to add the ApiClient to
     * @param logger  Logger to log debug information
     * @return ResultHandler which adds an ApiClient result to a Context.
     */
    public static ResultHandler<ApiClient> createAddApiClientToContextResultHandler(Context context, Logger logger) {
        return apiClient -> {
            logger.debug("Adding apiClient: {} to AttributesContext[\"{}\"]", apiClient, API_CLIENT_ATTR_KEY);
            context.asContext(AttributesContext.class).getAttributes().put(API_CLIENT_ATTR_KEY, apiClient);
        };
    }

    public FetchApiClientFilter(ApiClientService apiClientService, String accessTokenClientIdClaim) {
        Reject.ifNull(apiClientService, "apiClientService must be provided");
        Reject.ifBlank(accessTokenClientIdClaim, "accessTokenClientIdClaim must be provided");
        this.accessTokenClientIdClaim = accessTokenClientIdClaim;
        this.apiClientService = apiClientService;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final OAuth2Context oAuth2Context = context.asContext(OAuth2Context.class);
        final Map<String, Object> info = oAuth2Context.getAccessToken().getInfo();
        if (!info.containsKey(accessTokenClientIdClaim)) {
            logger.error("Access token is missing required \"{}\" claim", accessTokenClientIdClaim);
            return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        }
        final String clientId = (String)info.get(accessTokenClientIdClaim);

        return apiClientService.get(context, clientId)
                               .thenOnResult(createAddApiClientToContextResultHandler(context, logger))
                               .thenAsync(apiClient -> next.handle(context, request),
                                          this::handleApiClientServiceException, this::handleUnexpectedException);
    }

    private Promise<Response, NeverThrowsException> handleApiClientServiceException(ApiClientServiceException ex) {
        // Handles the case where the client has a valid access token but their ApiClient has been deleted from the data store
        if (ex.getErrorCode() == ErrorCode.DELETED || ex.getErrorCode() == ErrorCode.NOT_FOUND) {
            logger.warn("Failed to get ApiClient due to: {}", ex.getErrorCode(), ex);
            return newResultPromise(new Response(Status.UNAUTHORIZED).setEntity(json(object(field("error",
                                                                                                  "client registration is invalid")))));
        } else {
            return handleUnexpectedException(ex);
        }
    }

    private Promise<Response, NeverThrowsException> handleUnexpectedException(Exception ex) {
        logger.error("Failed to get ApiClient from idm due to an unexpected exception", ex);
        return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
    }

    /**
     * Responsible for creating the {@link FetchApiClientFilter}
     *
     * Mandatory config:
     * - apiClientService: reference to an {@link ApiClientService} implementation heap object to use to retrieve the {@link ApiClient}
     *
     * Optional config:
     * - accessTokenClientIdClaim: name of the claim used to extract the client_id from the access_token, defaults to "aud"
     * <p>
     * Example config:
     * {
     *           "comment": "Add ApiClient data to the context attributes",
     *           "name": "FetchApiClientFilter",
     *           "type": "FetchApiClientFilter",
     *           "config": {
     *             "apiClientService": "IdmApiClientService"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final String accessTokenClientIdClaim = config.get("accessTokenClientIdClaim")
                                                          .defaultTo(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM)
                                                          .asString();

            final ApiClientService apiClientService = config.get("apiClientService").as(requiredHeapObject(heap, ApiClientService.class));
            return new FetchApiClientFilter(apiClientService, accessTokenClientIdClaim);
        }
    }

}
