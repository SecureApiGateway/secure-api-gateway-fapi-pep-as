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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.Reject.checkNotBlank;
import static org.forgerock.util.Reject.checkNotNull;
import static org.forgerock.util.promise.NeverThrowsException.neverThrown;

import java.net.URI;

import org.forgerock.http.Client;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.Reject;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.service.ApiClientOrganisationService;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException;
import com.forgerock.sapi.gateway.dcr.service.ApiClientServiceException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.models.ApiClientOrganisation;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

public class IdmApiClientOrganisationService implements ApiClientOrganisationService {

    static final String DEFAULT_API_CLIENT_ORG_OBJ_NAME = "apiClientOrg";

    /**
     * HTTP Status code returned by IDM when the resource’s current version does not match the version provided.
     * <p>
     * Returned by IDM when attempting to create an {@link ApiClientOrganisation} that already exists
     * See: <a href="https://backstage.forgerock.com/docs/idm/7.4/crest/crest-status-codes.html">crest-status-codes</a>
     */
    private static final int HTTP_STATUS_PRECONDITION_FAILED = 412;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Client httpClient;

    /**
     * The base uri to the IDM managed objects endpoints
     * <p>
     * Of the form: https://$IDM_HOST/openidm/managed
     */
    private final String idmManagedObjectsBaseUri;

    /**
     * Name of the ApiClientOrganisation managed object name in IDM  - defaults to {@link #DEFAULT_API_CLIENT_ORG_OBJ_NAME}
     */
    private final String apiClientOrgManagedObjName;

    public IdmApiClientOrganisationService(Client httpClient, String idmManagedObjectsBaseUri) {
        this(httpClient, idmManagedObjectsBaseUri, DEFAULT_API_CLIENT_ORG_OBJ_NAME);
    }

    public IdmApiClientOrganisationService(Client httpClient, String idmManagedObjectsBaseUri, String apiClientOrgManagedObjName) {
        this.httpClient = checkNotNull(httpClient, "httpClient must be provided");
        this.idmManagedObjectsBaseUri = sanitizeBaseUri(checkNotBlank(idmManagedObjectsBaseUri, "idmManagedObjectsBaseUri must be provided"));
        this.apiClientOrgManagedObjName = checkNotBlank(apiClientOrgManagedObjName, "apiClientOrgManagedObjName must be provided");
    }

    private static String sanitizeBaseUri(String idmApiClientBaseUri) {
        if (idmApiClientBaseUri.endsWith("/")) {
            return idmApiClientBaseUri.substring(0, idmApiClientBaseUri.length() - 1);
        }
        return idmApiClientBaseUri;
    }

    @VisibleForTesting
    URI buildApiClientOrgUri(String apiClientOrgId) {
        return URI.create(idmManagedObjectsBaseUri + "/" + apiClientOrgManagedObjName + "/" + apiClientOrgId);
    }

    @Override
    public Promise<ApiClientOrganisation, ApiClientServiceException> createApiClientOrganisation(SoftwareStatement softwareStatement) {
        Reject.ifNull(softwareStatement, "softwareStatement must be provided");
        final String organisationId = softwareStatement.getOrgId();
        final String organisationName = softwareStatement.getOrgName();

        // Create using a PUT request to prevent errors occurring if we attempt to create an org that already exists
        // https://backstage.forgerock.com/docs/idm/7.4/crest/crest-create.html
        Request request = new Request();
        request.setMethod("PUT");
        request.setUri(buildApiClientOrgUri(organisationId));
        // Prevent updating an existing object
        request.addHeaders(new GenericHeader("If-None-Match", "*"));
        request.setEntity(json(object(field("_id",  organisationId),
                                      field("id",   organisationId),
                                      field("name", organisationName))));

        logger.debug("Attempting to create organisation - id: {}, name: {}", organisationId, organisationName);
        return httpClient.send(request)
                .then(response -> {
                    if (!response.getStatus().isSuccessful()
                            && response.getStatus().getCode() != HTTP_STATUS_PRECONDITION_FAILED) {
                        final String errorMessage = "Unexpected IDM response: " + response.getStatus().getCode()
                                + " returned when creating ApiClientOrg[id: " + organisationId + ", name: " + organisationName + "]";
                        logger.error(errorMessage);
                        throw new ApiClientServiceException(ErrorCode.SERVER_ERROR, errorMessage);
                    }

                    // No need to decode the response body as all the fields are known (also 412 Pre-condition failed responses do not contain a json entity)
                    final ApiClientOrganisation apiClientOrganisation = new ApiClientOrganisation(organisationId, organisationName);
                    logger.debug("Organisation: {} created or already exists", apiClientOrganisation);
                    return apiClientOrganisation;
                }, neverThrown());
    }

    public static class Heaplet extends BaseIdmServiceHeaplet {
        @Override
        public Object create() throws HeapException {
            return new IdmApiClientOrganisationService(createHttpClient(), getIdmManagedObjectsBaseUri(),
                                                       getApiClientOrgManagedObjName());
        }

    }
}
