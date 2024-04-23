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

import static java.util.Objects.requireNonNull;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;

import java.util.concurrent.atomic.AtomicReference;
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
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;

/**
 * Implementation of the {@link FetchApiClientFilter} which is specialised for use in an IG route which the {@link ApiClient}
 * needs to be fetched on the response path. This typically occurs when IG is reverse proxying an OAuth2.0 endpoint
 * of the AS, this ensures that the AS has successfully authenticated the client before fetching the ApiClient data.
 * <p>
 * The ApiClient is fetched form the data store using the OAuth2.0 client_id as the key. The client_id is determined
 * using configurable Functions which can retrieve the value from the {@link Request} or {@link Response} object.
 * <p>
 * One of requestClientIdRetriever or responseClientIdRetriever fields may be configured.
 * The factory methods handle constructing the filter and configuring the retriever correctly, see:
 * <ul>
 *     <li>{@link #createFilterWithRequestClientIdRetriever(ApiClientService, Function)}</li>
 *     <li>{@link #createFilterWithResponseClientIdRetriever(ApiClientService, Function)}</li>
 * </ul>
 * <p>
 * The {@link ApiClient} that is fetched is made accessible via the AttributesContext as key: "apiClient",
 * other filters in the chain can then access this data using the context.
 */
public class ResponsePathFetchApiClientFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResponsePathFetchApiClientFilter.class);

    /**
     * Service which can retrieve ApiClient data
     */
    private final ApiClientService apiClientService;

    /**
     * Function that can retrieve the clientId of the ApiClient from the Request.
     */
    private final Function<Request, Promise<String, NeverThrowsException>> requestClientIdRetriever;

    /**
     * Function that can retrieve the clientId of the ApiClient from the Response.
     */
    private final Function<Response, Promise<String, NeverThrowsException>> responseClientIdRetriever;

    /**
     * Factory capable of producing OAuth2.0 compliant HTTP Responses for error conditions.
     */
    private final OAuthErrorResponseFactory errorResponseFactory = new OAuthErrorResponseFactory(new ContentTypeFormatterFactory());

    /**
     * Creates a filter which retrieves the client_id from the Request object.
     */
    public static ResponsePathFetchApiClientFilter createFilterWithRequestClientIdRetriever(ApiClientService apiClientService,
                                                                                            Function<Request, Promise<String, NeverThrowsException>> requestClientIdRetriever) {
        return new ResponsePathFetchApiClientFilter(requireNonNull(apiClientService, "apiClientService must be provide"),
                                                    requireNonNull(requestClientIdRetriever, "requestClientIdRetriever must be provided"),
                                                    null);

    }

    /**
     * Creates a filter which retrieves the client_id from the Response object
     */
    public static ResponsePathFetchApiClientFilter createFilterWithResponseClientIdRetriever(ApiClientService apiClientService,
                                                                                              Function<Response, Promise<String, NeverThrowsException>> responseClientIdRetriever) {
        return new ResponsePathFetchApiClientFilter(requireNonNull(apiClientService, "apiClientService must be provide"),
                                                    null,
                                                    requireNonNull(responseClientIdRetriever, "responseClientIdRetriever must be provided"));

    }

    private ResponsePathFetchApiClientFilter(ApiClientService apiClientService,
                                             Function<Request, Promise<String, NeverThrowsException>> requestClientIdRetriever,
                                             Function<Response, Promise<String, NeverThrowsException>> responseClientIdRetriever) {
        this.apiClientService = apiClientService;
        Reject.ifTrue(requestClientIdRetriever != null && responseClientIdRetriever != null,
                "Only 1 of requestClientIdRetriever or responseClientIdRetriever can be provided");
        this.requestClientIdRetriever = requestClientIdRetriever;
        this.responseClientIdRetriever = responseClientIdRetriever;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final AtomicReference<String> clientIdReference = new AtomicReference<>();
        final Promise<Void, NeverThrowsException> requestClientIdPromise = retrieveClientIdFromRequest(request, clientIdReference);
        return next.handle(context, request).thenAsync(response -> {
                if (response.getStatus().isServerError() || response.getStatus().isClientError()) {
                    return Promises.newResultPromise(response);
                } else {
                    final Promise<Void, NeverThrowsException> responseClientIdPromise = retrieveClientIdFromResponse(response, clientIdReference);
                    return Promises.when(requestClientIdPromise, responseClientIdPromise).thenAsync(ignored -> {
                        final String clientId = clientIdReference.get();
                        if (clientId == null) {
                            LOGGER.error("Authorize request invalid - unable to locate client_id");
                            return Promises.newResultPromise(
                                    errorResponseFactory.invalidRequestErrorResponse(request.getHeaders().get(HttpHeaderNames.ACCEPT),
                                            "'client_id' is missing in the request."));
                        }

                        return apiClientService.getApiClient(clientId)
                                               .thenOnResult(FetchApiClientFilter.createAddApiClientToContextResultHandler(context, LOGGER))
                                               .then(apiClient -> response, // return the original response from the upstream
                                                     this::handleApiClientServiceException, this::handleUnexpectedException);
                    });
                }
            });
    }

    private Promise<Void, NeverThrowsException> retrieveClientIdFromRequest(Request request, AtomicReference<String> clientIdReference) {
        final Promise<Void, NeverThrowsException> requestClientIdPromise;
        if (requestClientIdRetriever != null) {
            requestClientIdPromise = requestClientIdRetriever.apply(request)
                                                             .thenOnResult(clientIdReference::set)
                                                             .thenDiscardResult();
        } else {
            requestClientIdPromise = Promises.newVoidResultPromise();
        }
        return requestClientIdPromise;
    }

    private Promise<Void, NeverThrowsException> retrieveClientIdFromResponse(Response response, AtomicReference<String> clientIdReference) {
        final Promise<Void, NeverThrowsException> responseClientIdPromise;
        if (responseClientIdRetriever != null) {
            responseClientIdPromise = responseClientIdRetriever.apply(response)
                                                               .thenOnResult(clientIdReference::set)
                                                               .thenDiscardResult();
        } else {
            responseClientIdPromise = Promises.newVoidResultPromise();
        }
        return responseClientIdPromise;
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

}
