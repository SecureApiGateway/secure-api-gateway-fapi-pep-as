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
package com.forgerock.sapi.gateway.dcr.models;

import org.forgerock.util.Reject;

/**
 * Data object which represents an Organisation to which one or more {@link ApiClient} objects belong
 *
 * @param id   Unique identifier of this organisation.
 * @param name Organisation name, typically the company name.
 */
public record ApiClientOrganisation(String id, String name) {

    public ApiClientOrganisation {
        Reject.ifBlank(id, "id must be provided");
        Reject.ifBlank(name, "name must be provided");
    }

    @Override
    public String toString() {
        return "ApiClientOrganisation{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                '}';
    }
}
