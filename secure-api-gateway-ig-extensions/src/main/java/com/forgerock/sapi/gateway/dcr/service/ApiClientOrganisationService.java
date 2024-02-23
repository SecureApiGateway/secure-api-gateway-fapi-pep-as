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
import com.forgerock.sapi.gateway.dcr.models.ApiClientOrganisation;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

/**
 * Service which handles managing {@link ApiClientOrganisation} objects in a data store.
 * <p>
 * Currently only supports Creates.
 * <p>
 * Reads are handled by fetching an {@link ApiClient} using the {@link ApiClientService}, the returned {@link ApiClient}
 * will have the organisation field populated.
 * <p>
 * Full CRUD support can be added in the future when it is needed.
 */
public interface ApiClientOrganisationService {

    /**
     * Creates an {@link ApiClientOrganisation} in the data store
     *
     * @param softwareStatement {@link SoftwareStatement} belonging to the organisation to create
     * @return Promise containing either the created {@link ApiClientOrganisation} or an {@link ApiClientServiceException}
     * if an error occurs.
     */
    Promise<ApiClientOrganisation, ApiClientServiceException> createApiClientOrganisation(SoftwareStatement softwareStatement);

}
