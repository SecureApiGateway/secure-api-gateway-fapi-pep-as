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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;

import java.util.List;
import java.util.function.Function;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.error.OAuthErrorResponseFactory;
import com.forgerock.sapi.gateway.common.rest.ContentTypeFormatterFactory;
import com.forgerock.sapi.gateway.common.rest.HttpHeaderNames;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;

/**
 * Implementation of the {@link FetchApiClientFilter} which is specialised for use in an IG route reverse proxying an
 * OAuth2 authorization endpoint implemented as per <a href="https://www.rfc-editor.org/info/rfc6749">RFC 6749</a>
 * <p>
 * The client_id request URI parameter is used to retrieve the {@link ApiClient} which is then made accessible via the
 * AttributesContext as key: "apiClient", other filters in the chain can then access this data using the context.
 * <p>
 * This implementation runs on the response path (rather than the request path), this ensures that the AS has
 * successfully authenticated the client before fetching the ApiClient data
 */
public class AuthorizeResponseFetchApiClientFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizeResponseFetchApiClientFilter.class);

    /**
     * Service which can retrieve ApiClient data
     */
    private final ApiClientService apiClientService;

    /**
     * Function that can retrieve the clientId of the ApiClient from the Request
     */
    private final Function<Request, Promise<String, NeverThrowsException>> clientIdRetriever;

    /**
     * Factory capable of producing OAuth2.0 compliant HTTP Responses for error conditions.
     */
    private final OAuthErrorResponseFactory errorResponseFactory = new OAuthErrorResponseFactory(new ContentTypeFormatterFactory());

    public AuthorizeResponseFetchApiClientFilter(ApiClientService apiClientService,
                                                 Function<Request, Promise<String, NeverThrowsException>> clientIdRetriever) {
        this.apiClientService = Reject.checkNotNull(apiClientService, "apiClientService must be provided");
        this.clientIdRetriever = Reject.checkNotNull(clientIdRetriever, "clientIdRetriever must be provided");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        return clientIdRetriever.apply(request).thenAsync(clientId -> {
            if (clientId == null) {
                LOGGER.error("Authorize request missing mandatory client_id param");
                return Promises.newResultPromise(
                        errorResponseFactory.invalidRequestErrorResponse(request.getHeaders().get(HttpHeaderNames.ACCEPT), "'client_id' is missing in the request."));
            }
            return next.handle(context, request).thenAsync(response -> {
                if (response.getStatus().isServerError() || response.getStatus().isClientError()) {
                    return Promises.newResultPromise(response);
                } else {
                    return apiClientService.getApiClient(clientId)
                            .thenOnResult(FetchApiClientFilter.createAddApiClientToContextResultHandler(context, LOGGER))
                            .then(apiClient -> response, // return the original response from the upstream
                                    this::handleApiClientServiceException, this::handleUnexpectedException);

                }
            });
        });
    }

    private Response handleApiClientServiceException(ApiClientServiceException ex) {
        // Handles the case where the ApiClient has been deleted from the data store
        if (ex.getErrorCode() == ErrorCode.DELETED || ex.getErrorCode() == ErrorCode.NOT_FOUND) {
            LOGGER.warn("Failed to get ApiClient due to: {}", ex.getErrorCode(), ex);
            return new Response(Status.UNAUTHORIZED).setEntity(json(field("error", "client registration is invalid")));
        } else {
            return handleUnexpectedException(ex);
        }
    }

    private Response handleUnexpectedException(Exception ex) {
        LOGGER.error("Failed to get ApiClient from idm due to an unexpected exception", ex);
        return new Response(Status.INTERNAL_SERVER_ERROR);
    }

    /**
     * Helper function capable of retrieving the client_id parameter from the Request's Query params.
     *
     * @return Promise<String, NeverThrowsException> which returns the client_id or null if it does not exist
     */
    static Function<Request, Promise<String, NeverThrowsException>> queryParamClientIdRetriever() {
        return request -> {
            final List<String> clientIdParams = request.getQueryParams().get("client_id");
            if (clientIdParams != null && clientIdParams.size() > 0) {
                return Promises.newResultPromise(clientIdParams.get(0));
            } else {
                return Promises.newResultPromise(null);
            }
        };
    }

    /**
     * Helper function capable of retrieving the client_id parameter from the Request's Form entity.
     *
     * @return Promise<String, NeverThrowsException> which returns the client_id or null if it does not exist
     */
    static Function<Request, Promise<String, NeverThrowsException>> formClientIdRetriever() {
        return request -> request.getEntity().getFormAsync()
                .then(form -> form.getFirst("client_id"))
                .thenCatch(ioe -> {
                    LOGGER.warn("Failed to extract client_id from /par request due to exception", ioe);
                    return null;
                });
    }

}
