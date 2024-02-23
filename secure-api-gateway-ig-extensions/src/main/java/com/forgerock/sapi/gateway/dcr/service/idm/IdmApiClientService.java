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
package com.forgerock.sapi.gateway.dcr.service.idm;

import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientOrganisationService.DEFAULT_API_CLIENT_ORG_OBJ_NAME;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.NeverThrowsException.neverThrownAsync;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.forgerock.http.Client;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.Reject;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

/**
 * ApiClientService implementation which manages ApiClient data in IDM
 */
public class IdmApiClientService implements ApiClientService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    static final String DEFAULT_API_CLIENT_OBJ_NAME = "apiClient";

    /**
     * The base uri to use in GET requests to IDM to query for the apiClient
     * <p>
     * Of the form: https://$IDM_HOST/openidm/managed
     */
    private final String idmManagedObjectsBaseUri;

    /**
     * The name of the ApiClient managed object in IDM - defaults to {@link #DEFAULT_API_CLIENT_OBJ_NAME}
     */
    private final String apiClientManagedObjName;

    /**
     * The name of the ApiClientOrganisation managed object in IDM - defaults to {@link IdmApiClientOrganisationService#DEFAULT_API_CLIENT_ORG_OBJ_NAME}
     */
    private final String apiClientOrgManagedObjName;

    /**
     * Value of the _fields IDM query param to use when querying for ApiClient data in IDM.
     */
    private final String apiClientFieldsValue;

    /**
     * URI of the endpoint used to create ApiClients in IDM - this is fixed and can be reused across create requests
     */
    private final URI createApiClientUri;

    /**
     * The HTTP client to use when calling IDM.
     * Must be configured to provide credentials that allow access to the IDM REST API
     */
    private final Client httpClient;

    /**
     * Decoder that transforms IDM response json into ApiClient objects
     */
    private final IdmApiClientDecoder idmApiClientDecoder;

    public IdmApiClientService(Client httpClient, String idmManagedObjectsBaseUri, IdmApiClientDecoder idmApiClientDecoder) {
        this(httpClient, idmManagedObjectsBaseUri, DEFAULT_API_CLIENT_OBJ_NAME, DEFAULT_API_CLIENT_ORG_OBJ_NAME, idmApiClientDecoder);
    }

    public IdmApiClientService(Client httpClient, String idmManagedObjectsBaseUri, String apiClientManagedObjName,
                              String apiClientOrgManagedObjName, IdmApiClientDecoder idmApiClientDecoder) {

        this.idmManagedObjectsBaseUri = sanitizeBaseUri(idmManagedObjectsBaseUri);
        this.apiClientManagedObjName = Reject.checkNotBlank(apiClientManagedObjName, "apiClientManagedObjName must be provided");
        this.apiClientOrgManagedObjName = Reject.checkNotBlank(apiClientOrgManagedObjName, "apiClientOrgManagedObjName must be provided");
        this.httpClient = Reject.checkNotNull(httpClient, "httpClient must be provided");
        this.idmApiClientDecoder = Reject.checkNotNull(idmApiClientDecoder, "idmApiClientDecoder must be provided");

        // Query for the all the apiClient fields and the full apiClientOrg relationship object
        this.apiClientFieldsValue = apiClientOrgManagedObjName + "/*,*";
        try {
            this.createApiClientUri = createIdmUri(null, Map.of("_fields", apiClientFieldsValue));
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Failed to create URI", e);
        }

        logger.info("Configuration - idmManagedObjectsBaseUri: {}, createApiClientUri: {}, apiClientOrgManagedObjName: {}",
                idmManagedObjectsBaseUri, createApiClientUri, apiClientOrgManagedObjName);
    }

    private static String sanitizeBaseUri(String idmApiClientBaseUri) {
        Reject.checkNotBlank(idmApiClientBaseUri, "idmManagedObjectsBaseUri must be provided");
        // Strip any trailing slash
        if (idmApiClientBaseUri.endsWith("/")) {
            return idmApiClientBaseUri.substring(0, idmApiClientBaseUri.length() - 1);
        }
        return idmApiClientBaseUri;
    }

    @VisibleForTesting
    URI createIdmUri(String clientId, Map<String, String> queryParams) throws URISyntaxException {
        final Form form = new Form();
        if (queryParams != null) {
            queryParams.forEach(form::putSingle);
        }

        final MutableUri idmUri = MutableUri.uri(idmManagedObjectsBaseUri + "/" + apiClientManagedObjName);
        if (clientId != null) {
            idmUri.setPath(idmUri.getPath() + '/' + clientId);
        }
        idmUri.setQuery(form.toQueryString());
        return idmUri.asURI();
    }

    @Override
    public Promise<ApiClient, ApiClientServiceException> createApiClient(String oAuth2ClientId, SoftwareStatement softwareStatement) {
        Reject.ifBlank(oAuth2ClientId, "oAuth2ClientId must be provided");
        Reject.ifNull(softwareStatement, "softwareStatement must be provided");
        logger.debug("Attempting to create ApiClient for oAuth2ClientId: {} and softwareStatement: {}", oAuth2ClientId, softwareStatement);

        final Request createApiClientRequest = new Request().setMethod("POST")
                .setUri(createApiClientUri)
                .setEntity(buildApiClientRequestJson(oAuth2ClientId, softwareStatement));
        return httpClient.send(createApiClientRequest)
                         .thenAsync(this::decodeIdmResponse,
                                    neverThrownAsync());
    }

    @VisibleForTesting
    JsonValue buildApiClientRequestJson(String oAuth2ClientId, SoftwareStatement softwareStatement) {
        final JsonValue json = json(object(
                field("_id", oAuth2ClientId),
                field("id", softwareStatement.getSoftwareId()),
                field("name", softwareStatement.getClientName()),
                field("ssa", softwareStatement.getB64EncodedJwtString()),
                field("roles", softwareStatement.getRoles()),
                field("oauth2ClientId", oAuth2ClientId),
                field("deleted", false),
                field("apiClientOrg",
                        object(field("_ref", "managed/" + apiClientOrgManagedObjName + "/" + softwareStatement.getOrgId())))
        ));
        if (softwareStatement.hasJwksUri()){
            json.put("jwksUri", softwareStatement.getJwksUri().toString());
        } else {
            json.put("jwks", softwareStatement.getJwksSet().toJsonValue());
        }
        return json;
    }

    private Promise<ApiClient, ApiClientServiceException> decodeIdmResponse(Response response) throws ApiClientServiceException {
        return decodeIdmResponse(response, false);
    }

    private Promise<ApiClient, ApiClientServiceException> decodeIdmResponse(Response response, boolean allowDeleted) throws ApiClientServiceException {
        if (!response.getStatus().isSuccessful()) {
            throw new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Failed to get ApiClient from IDM, response status: " + response.getStatus());
        }
        return response.getEntity().getJsonAsync()
                       .then(json -> {
                           final ApiClient apiClient;
                           try {
                               apiClient = idmApiClientDecoder.decode(json(json));
                           } catch (RuntimeException ex) {
                               throw new ApiClientServiceException(ErrorCode.DECODE_FAILED, "Failed to decode apiClient response json", ex);
                           }
                           if (apiClient.isDeleted() && !allowDeleted) {
                               throw new ApiClientServiceException(ErrorCode.DELETED, "ApiClient apiClientId: " + apiClient.getOAuth2ClientId() + " has been deleted");
                           }
                           return apiClient;
                       }, ioe -> {
                           throw new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Failed to get response json entity", ioe);
                       });
    }

    @Override
    public Promise<ApiClient, ApiClientServiceException> getApiClient(String oAuth2ClientId) {
        Reject.ifBlank(oAuth2ClientId, "apiClientId must be provided");
        try {
            logger.debug("Attempting to getApiClient for apiClientId: {}", oAuth2ClientId);
            final Request getApiClientRequest = new Request().setMethod("GET")
                                                             .setUri(createIdmUri(oAuth2ClientId, Map.of("_fields", apiClientFieldsValue)));
            return httpClient.send(getApiClientRequest)
                             .thenAsync(response -> decodeIdmResponseForExistingApiClient(oAuth2ClientId, response, false),
                                        neverThrownAsync());
        } catch (URISyntaxException e) {
            return apiClientServiceExceptionPromise(e);
        }
    }

    private static Promise<ApiClient, ApiClientServiceException> apiClientServiceExceptionPromise(URISyntaxException e) {
        return Promises.newExceptionPromise(new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Failed to build request URI", e));
    }

    private Promise<ApiClient, ApiClientServiceException> decodeIdmResponseForExistingApiClient(String apiClientId, Response response, boolean allowDeleted) throws ApiClientServiceException {
        if (response.getStatus() == Status.NOT_FOUND) {
            throw new ApiClientServiceException(ErrorCode.NOT_FOUND, "ApiClient not found for apiClientId: " + apiClientId);
        }
        return decodeIdmResponse(response, allowDeleted);
    }

    @Override
    public Promise<ApiClient, ApiClientServiceException> updateApiClient(String oAuth2ClientId, SoftwareStatement softwareStatement) {
        Reject.ifBlank(oAuth2ClientId, "oAuth2ClientId must be provided");
        Reject.ifNull(softwareStatement, "softwareStatement must be provided");
        logger.debug("Attempting to update ApiClient for oAuth2ClientId: {} and softwareStatement: {}", oAuth2ClientId, softwareStatement);

        try {
            final Request createApiClientRequest = new Request().setMethod("PUT")
                                                                .setUri(createIdmUri(oAuth2ClientId,
                                                                                     Map.of("_fields", apiClientFieldsValue)))
                                                                .setEntity(buildApiClientRequestJson(oAuth2ClientId,
                                                                                                     softwareStatement));

            return httpClient.send(createApiClientRequest)
                             .thenAsync(response -> decodeIdmResponseForExistingApiClient(oAuth2ClientId, response, false),
                                        neverThrownAsync());
        } catch (URISyntaxException e) {
            return apiClientServiceExceptionPromise(e);
        }
    }

    /**
     * Deletes an ApiClient in IDM.
     * <p>
     * This is a soft delete, the ApiClient.deleted field is set to true by sending an IDM patch request
     *
     * @param oAuth2ClientId String the apiClientId to delete
     * @return Promise with either the deleted ApiClient as the result or an ApiClientServiceException
     * if the delete operation fails
     */
    @Override
    public Promise<ApiClient, ApiClientServiceException> deleteApiClient(String oAuth2ClientId) {
        Reject.ifBlank(oAuth2ClientId, "apiClientId must be provided");
        try {
            logger.info("Attempting to mark ApiClient: {} as deleted", oAuth2ClientId);
            final Request request = new Request().setMethod("POST")
                                                 .setUri(createIdmUri(oAuth2ClientId, Map.of("_action", "patch",
                                                                                          "_fields", apiClientFieldsValue)));
            request.setEntity(json(array(object(field("operation", "replace"),
                                                field("field", "deleted"),
                                                field("value", true)))));

            return httpClient.send(request)
                             .thenAsync(response -> decodeIdmResponseForExistingApiClient(oAuth2ClientId, response, true),
                                        neverThrownAsync());
        } catch (URISyntaxException e) {
            return apiClientServiceExceptionPromise(e);
        }
    }

    public static class Heaplet extends BaseIdmServiceHeaplet {
        @Override
        public Object create() throws HeapException {
            return new IdmApiClientService(createHttpClient(), getIdmManagedObjectsBaseUri(),
                    getApiClientManagedObjName(), getApiClientOrgManagedObjName(), new IdmApiClientDecoder());
        }

    }
}
