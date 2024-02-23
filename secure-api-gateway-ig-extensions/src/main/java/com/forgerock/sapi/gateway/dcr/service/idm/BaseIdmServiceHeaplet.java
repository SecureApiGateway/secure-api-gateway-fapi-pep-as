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
import static com.forgerock.sapi.gateway.dcr.service.idm.IdmApiClientService.DEFAULT_API_CLIENT_OBJ_NAME;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;

/**
 * Base Heaplet used to create Idm services, contains helper methods for retrieving config common to Idm services.
 * <p>
 * See {@link IdmApiClientService.Heaplet} for an example implementation.
 */
public abstract class BaseIdmServiceHeaplet extends GenericHeaplet {

    protected Client createHttpClient() throws HeapException {
        final Handler clientHandler = config.get("clientHandler").as(requiredHeapObject(heap, Handler.class));
        return new Client(clientHandler);
    }

    protected String getIdmManagedObjectsBaseUri() {
        return config.get("idmManagedObjectsBaseUri").required().asString();
    }

    protected String getApiClientManagedObjName() {
        return config.get("apiClientManagedObjName").defaultTo(DEFAULT_API_CLIENT_OBJ_NAME).asString();
    }

    protected String getApiClientOrgManagedObjName() {
        return config.get("apiClientOrgManagedObjName").defaultTo(DEFAULT_API_CLIENT_ORG_OBJ_NAME).asString();
    }
}
