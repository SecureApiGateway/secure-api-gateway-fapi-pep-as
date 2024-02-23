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
package com.forgerock.sapi.gateway.dcr.service;

import org.forgerock.util.promise.Promise;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

/**
 * Service which handles CRUD operations for {@link ApiClient} objects for a particular data store.
 */
public interface ApiClientService {


    /**
     * Creates an {@link ApiClient} using DCR data
     *
     * @param oAuth2ClientId    the OAuth2.0 client_id from the DCR response
     * @param softwareStatement the SoftwareStatement used in the DCR request used to create the OAuth2.0 client
     * @return Promise which either returns the created {@link ApiClient} or an {@link ApiClientServiceException} if an error occurs.
     */
    Promise<ApiClient, ApiClientServiceException> createApiClient(String oAuth2ClientId, SoftwareStatement softwareStatement);

    /**
     * Gets an {@link ApiClient}
     *
     * @param oAuth2ClientId the OAuth2.0 client_id of the {@link ApiClient}
     * @return Promise which either returns the ApiClient or an {@link ApiClientServiceException} if an error occurs.
     */
    Promise<ApiClient, ApiClientServiceException> getApiClient(String oAuth2ClientId);

    /**
     * Updates an {@link ApiClient} using DCR data
     *
     * @param oAuth2ClientId    the OAuth2.0 client_id from the DCR response
     * @param softwareStatement the SoftwareStatement used in the DCR request used to create the OAuth2.0 client
     * @return Promise which either returns the updated {@link ApiClient} or an {@link ApiClientServiceException} if an error occurs.
     */
    Promise<ApiClient, ApiClientServiceException> updateApiClient(String oAuth2ClientId, SoftwareStatement softwareStatement);

    /**
     * Deletes an {@link ApiClient}
     *
     * @param oAuth2ClientId the OAuth2.0 client_id of the {@link ApiClient}
     * @return Promise which either returns the deleted {@link ApiClient} or an {@link ApiClientServiceException} if an error occurs.
     */
    Promise<ApiClient, ApiClientServiceException> deleteApiClient(String oAuth2ClientId);

}
