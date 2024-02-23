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
package com.forgerock.sapi.gateway.jwks;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;

/**
 * Service which retrieves the JWKSet for an ApiClient.
 */
public interface ApiClientJwkSetService {

    /**
     * Get a {@link JWKSet} for an {@link ApiClient} that is registered with a {@link TrustedDirectory}
     * @param apiClient the ApiClient to get the JWKSet for, this contains the keys for the ApiClient that are registed with the TrustedDirectory
     * @param trustedDirectory the TrustedDirectory that the ApiClient is registered with
     * @return Promise containing with the JWKSet or {@link FailedToLoadJWKException} if an error occurred.
     */
    Promise<JWKSet, FailedToLoadJWKException> getJwkSet(ApiClient apiClient, TrustedDirectory trustedDirectory);
}
