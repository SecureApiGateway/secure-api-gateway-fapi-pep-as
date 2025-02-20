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

import static com.forgerock.sapi.gateway.util.ContextUtils.REGISTRATION_REQUEST_KEY;
import static com.forgerock.sapi.gateway.util.ContextUtils.getRequiredAttributeAsType;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.Reject.checkNotNull;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.util.List;
import java.util.Optional;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.fapi.apiclient.ApiClient;
import org.forgerock.openig.fapi.apiclient.ApiClientOrganisation;
import org.forgerock.openig.fapi.apiclient.service.ApiClientOrganisationService;
import org.forgerock.openig.fapi.apiclient.service.ApiClientService;
import org.forgerock.openig.fapi.apiclient.service.ApiClientServiceException;
import org.forgerock.openig.fapi.dcr.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.Function;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filter to manage {@link ApiClient}s in a data store as part of protecting an OAuth2.0 /register (DCR) endpoint.
 * <p>
 * Supports CRUD operations for {@link ApiClient}s as part of DCR calls, the following operations are supported:
 * <ul>
 *     <li>
 *         POST requests create a new ApiClient and ApiClientOrganisation (if the organisation does not already exist)
 *         in the data store.
 *     </li>
 *     <li>
 *         GET requests fetch the ApiClient from the data store.
 *     </li>
 *     <li>
 *         PUT requests update the ApiClient in the data store.
 *     </li>
 *     <li>
 *         DELETE requests delete the ApiClient from the data store.
 *     </li>
 * </ul>
 * All operations add the ApiClient object to the AttributesContext using key: {@link FetchApiClientFilter#API_CLIENT_ATTR_KEY},
 * this makes the ApiClient available to other filters.
 * <p>
 * These operations occur on the response path and only take place if the response from the upstream is a success,
 * this ensures that the Authorization Server has validated and processed the request first.
 * <p>
 * Taking the POST flow as an example, in this flow the client is completing a new DCR in order to register themselves
 * as an OAuth2.0 client, an ApiClient is created in the data store if registration is successful.
 * <p>
 * The ApiClient stores information about the registration that is used when this client makes calls to other endpoints
 * protected by SAPI-G in order to enforce security rules e.g. that the ApiClient has the correct roles to perform an
 * operation or to validate the client's mtls certificate.
 */
public class ManageApiClientFilter implements Filter {

    /**
     * Locates the OAuth2.0 client_id parameter for an invocation of this filter
     */
    public interface ClientIdRequestParameterLocator {
        /**
         * Locates the OAuth2.0 client_id in either the HTTP Request that is being processed or its associated Context.
         *
         * @param context Context used to invoke this filter for a particular request
         * @param request Request being processed by the filter
         * @return OAuth2.0 client_id parameter or null if one could not be found. Implementations should not throw
         * any exceptions and should return null instead.
         */
        String locateClientId(Context context, Request request);
    }

    /**
     * ClientIdLocator that extract the client_id from a request URI query parameter.
     * <p>
     * This is designed to work with the AM implementation of the DCR management protocol,
     * see documentation:
     * <a href="https://backstage.forgerock.com/docs/am/7.4/oidc1-guide/oauth2-dynamic-client-registration.html#dynamic-client-registration-management">Manage client profiles</a>
     */
    public static class QueryParamClientIdRequestParameterLocator implements ClientIdRequestParameterLocator {
        @Override
        public String locateClientId(Context context, Request request) {
            return request.getQueryParams().getFirst("client_id");
        }

        public static class Heaplet extends GenericHeaplet {
            @Override
            public Object create() throws HeapException {
                return new QueryParamClientIdRequestParameterLocator();
            }
        }
    }

    /**
     * ClientIdLocator that extracts the client_id from the request URI path. The last element of the paths is expected
     * to contain the client_id.
     * <p>
     * This implementation is designed to work with Authorization Servers that have implemented Dynamic Client Registration
     * management protocol as per: <a href="https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1">RFC 7592</a>
     * As this RFC is experimental, then flexibility is required to allow custom implementations to be plugged in as not
     * all Authorization Servers will follow the spec's suggestions.
     * <p>
     * Note: there is no way for this implementation to sanity check that the client_id is actually included as the
     * last element in the path, it will always return the last element of the path or null if there is no path.
     */
    public static class PathParamClientIdRequestParameterLocator implements ClientIdRequestParameterLocator {
        @Override
        public String locateClientId(Context context, Request request) {
            final List<String> pathElements = request.getUri().getPathElements();
            if (!pathElements.isEmpty()) {
                return pathElements.get(pathElements.size() - 1);
            }
            return null;
        }

        public static class Heaplet extends GenericHeaplet {
            @Override
            public Object create() throws HeapException {
                return new PathParamClientIdRequestParameterLocator();
            }
        }
    }

    private final Logger logger = LoggerFactory.getLogger(getClass());
    /**
     * Service to delegate {@link ApiClient} CRUD operations to.
     */
    private final ApiClientService apiClientService;
    /**
     * Service to delegate {@link ApiClientOrganisation} CRUD operations to.
     */
    private final ApiClientOrganisationService apiClientOrganisationService;
    private final ClientIdRequestParameterLocator clientIdRequestParameterLocator;

    public ManageApiClientFilter(ApiClientService apiClientService, ApiClientOrganisationService apiClientOrganisationService,
                                 ClientIdRequestParameterLocator clientIdRequestParameterLocator) {
        this.apiClientService = checkNotNull(apiClientService, "apiClientService must be provided");
        this.apiClientOrganisationService = checkNotNull(apiClientOrganisationService, "apiClientOrganisationService must be provided");
        this.clientIdRequestParameterLocator = checkNotNull(clientIdRequestParameterLocator, "clientIdLocator must be provided");
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        return next.handle(context, request).thenAsync(response -> {
            // If the upstream returns an error response then pass it on
            if (!response.getStatus().isSuccessful()) {
                return newResultPromise(response);
            }
            logger.debug("Upstream operation was successful - proceeding to handle ApiClient tasks");
            return switch (request.getMethod()) {
                case "GET" -> handleGetApiClient(context, request, response);
                case "POST" -> handleCreateApiClient(context, response);
                case "PUT" -> handleUpdateApiClient(context, response);
                case "DELETE" -> handleDeleteApiClient(context, request);
                default -> handleMethodNotAllowed();
            };
        });
    }

    private Promise<Response, NeverThrowsException> handleGetApiClient(Context context, Request request, Response response) {
        final Optional<String> clientIdOptional = invokeClientIdLocator(context, request);
        if (clientIdOptional.isEmpty()) {
            return newResultPromise(internalServerErrorResponse("client_id not found"));
        }
        final String clientId = clientIdOptional.get();
        return apiClientService.get(context, clientId)
                               .thenOnResult(apiClient -> storeApiClientInContext(context, apiClient))
                               .then(apiClient -> response,
                                     errorResponseHandler("Failed to get ApiClient"));
    }

    private Optional<String> invokeClientIdLocator(Context context, Request request) {
        try {
            return Optional.ofNullable(this.clientIdRequestParameterLocator.locateClientId(context, request));
        } catch (RuntimeException ex) {
            logger.warn("clientIdLocator: {} implementation threw an unexpected exception " +
                    "- implementations should return null when they are unable to locate the client_id",
                    clientIdRequestParameterLocator, ex);
            return Optional.empty();
        }
    }

    private Promise<Response, NeverThrowsException> handleCreateApiClient(Context context, Response response) {
        final SoftwareStatement softwareStatement = extractSoftwareStatement(context);
        return extractClientIdFromRegistrationResponse(response).thenAsync(clientIdOptional -> {
            if (clientIdOptional.isEmpty()) {
                return Promises.newResultPromise(internalServerErrorResponse("client_id field not found in registration response"));
            }
            return apiClientOrganisationService.create(context, softwareStatement)
                                               .thenAsync(apiClientOrg -> createApiClient(context, clientIdOptional.get(), softwareStatement)
                                                                            .then(apiClient -> response,
                                                                                    errorResponseHandler("Failed to create ApiClient")),
                                                         errorResponseHandlerAsync("Failed to create ApiClientOrganisation"));
        });
    }

    private static SoftwareStatement extractSoftwareStatement(Context context) {
        final RegistrationRequest registrationRequest = getRequiredAttributeAsType(context,
                                                                                   REGISTRATION_REQUEST_KEY,
                                                                                   RegistrationRequest.class);
        return registrationRequest.getSoftwareStatement();
    }

    /**
     * Extracts the OAuth2.0 client_id from a Dynamic Client Registration response.
     * See spec: <a href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">Client Information Response</a>
     *
     * @param response successful Response from the upstream Authorisation Server
     * @return Optional containing the OAuth2.0 client_id or an empty Optional if the client_id is not present or an
     * error occurs extracting the value.
     */
    private Promise<Optional<String>, NeverThrowsException> extractClientIdFromRegistrationResponse(Response response) {
        return response.getEntity().getJsonAsync().then(json -> {
            try {
                return Optional.of(json(json).get("client_id").required().asString());
            } catch (JsonException ex) {
                logger.debug("client_id field not found in json response");
                return Optional.empty();
            }
        }, ioe -> {
            logger.warn("Failed to extract client_id due to exception", ioe);
            return Optional.empty();
        });
    }

    private Promise<ApiClient, ApiClientServiceException> createApiClient(Context context, String oAuth2ClientId, SoftwareStatement softwareStatement) {
        return apiClientService.create(context, oAuth2ClientId, softwareStatement)
                               .thenOnResult(apiClient -> storeApiClientInContext(context, apiClient));
    }

    private void storeApiClientInContext(Context context, ApiClient apiClient) {
        logger.debug("Storing ApiClient with key: {} in AttributesContext", FetchApiClientFilter.API_CLIENT_ATTR_KEY);
        context.asContext(AttributesContext.class).getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);
    }

    private Promise<Response, NeverThrowsException> handleUpdateApiClient(Context context, Response response) {
        final SoftwareStatement softwareStatement = extractSoftwareStatement(context);

        return extractClientIdFromRegistrationResponse(response).thenAsync(clientIdOptional -> {
            if (clientIdOptional.isEmpty()) {
                return Promises.newResultPromise(internalServerErrorResponse("client_id field not found in registration response"));
            }
            return updateApiClient(context, clientIdOptional.get(), softwareStatement)
                        .then(apiClient -> response,
                              errorResponseHandler("Failed to update ApiClient"));
        });

    }

    private Promise<ApiClient, ApiClientServiceException> updateApiClient(Context context, String oAuth2ClientId, SoftwareStatement softwareStatement) {
        return apiClientService.update(context, oAuth2ClientId, softwareStatement)
                               .thenOnResult(apiClient -> storeApiClientInContext(context, apiClient));
    }

    /**
     * Handles deleting an ApiClient, adds the deleted client to the attributes context so that it can be used in
     * other filters (such as Audit or Metrics)
     * <p>
     * Produces a new Response with a 204 No Content status, the Response from the upstream is not used as AM does
     * not follow the spec and instead returns a 200 response. See spec: https://www.rfc-editor.org/rfc/rfc7592.html#section-2.3
     *
     * @param context Context used to invoke this filter
     * @param request Request used to invoke this filter
     * @return Promise containing either a Response, the status will be 204 No Content if processing is successful
     * otherwise an error response with a suitable error status will be used.
     */
    private Promise<Response, NeverThrowsException> handleDeleteApiClient(Context context, Request request) {
        final Optional<String> clientIdOptional = invokeClientIdLocator(context, request);
        if (clientIdOptional.isEmpty()) {
            return newResultPromise(internalServerErrorResponse("client_id not found"));
        }
        final String clientId = clientIdOptional.get();
        return apiClientService.delete(context, clientId)
                               .thenOnResult(apiClient -> storeApiClientInContext(context, apiClient))
                                // Return a 204 No Content response rather than the upstream response as some Authorization Servers (AM for example) return 200 OK
                               .then(apiClient -> new Response(Status.NO_CONTENT), errorResponseHandler("Failed to delete ApiClient"));
    }

    private AsyncFunction<ApiClientServiceException, Response, NeverThrowsException> errorResponseHandlerAsync(String errorMessage) {
        return ex -> newResultPromise(errorResponseHandler(errorMessage).apply(ex));
    }

    private Function<ApiClientServiceException, Response, NeverThrowsException> errorResponseHandler(String errorMessage) {
        return ex -> {
            logger.info("Handling error response for ApiClientServiceException with message: {}, ex: {}", errorMessage, ex);
                return switch (ex.getErrorCode()) {
                case DELETED -> unauthorizedErrorResponse(errorMessage);
                default -> internalServerErrorResponse(errorMessage);
                };
        };
    }
    private static Response internalServerErrorResponse(String message) {
        return new Response(Status.INTERNAL_SERVER_ERROR).setEntity(buildErrorEntity(message));
    }

    private static Response unauthorizedErrorResponse(String message) {
        return new Response(Status.UNAUTHORIZED).setEntity(buildErrorEntity(message));
    }

    private static JsonValue buildErrorEntity(String message) {
        return json(object(field("error", message)));
    }

    private Promise<Response, NeverThrowsException> handleMethodNotAllowed() {
        return newResultPromise(new Response(Status.METHOD_NOT_ALLOWED));
    }

    /**
     * Heaplet which creates a {@link ManageApiClientFilter}.
     * <p>
     * Mandatory config:
     * - apiClientService: reference to a {@link ApiClientService} heap object to use to retrieve the {@link ApiClient}
     * - apiClientOrgService: reference to a {@link ApiClientOrganisationService} heap object to use to create
     *                        {@link ApiClientOrganisation}s
     * - clientIdRequestParameterLocator: reference to a {@link ClientIdRequestParameterLocator} heap object to use to
     *                                    retrieve the client_id from the Request
     * <p>
     * Example config:
     * <pre>{@code
     * {
     *   "name": "ManageApiClientFilter",
     *   "type": "ManageApiClientFilter",
     *   "comment": "Filter to manage ApiClient data for DCRs in a repository",
     *   "config": {
     *     "apiClientService": "IdmApiClientService",
     *     "apiClientOrgService": "IdmApiClientOrgService",
     *     "clientIdRequestParameterLocator": "QueryParamClientIdRequestParameterLocator"
     *   }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {

        private ApiClientService getApiClientService() throws HeapException {
            return config.get("apiClientService").as(requiredHeapObject(heap, ApiClientService.class));
        }

        private ApiClientOrganisationService getApiClientOrganisationService() throws HeapException {
            return config.get("apiClientOrgService").as(requiredHeapObject(heap, ApiClientOrganisationService.class));
        }

        private ClientIdRequestParameterLocator getClientIdRequestParameterLocator() throws HeapException {
            return config.get("clientIdRequestParameterLocator").as(requiredHeapObject(heap, ClientIdRequestParameterLocator.class));
        }

        @Override
        public Object create() throws HeapException {
            return new ManageApiClientFilter(getApiClientService(), getApiClientOrganisationService(), getClientIdRequestParameterLocator());
        }
    }
}
