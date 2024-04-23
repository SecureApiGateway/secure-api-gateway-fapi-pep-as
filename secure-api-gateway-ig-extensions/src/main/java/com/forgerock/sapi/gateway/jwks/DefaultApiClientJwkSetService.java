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

import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;

/**
 * Service which retrieves the JWKSet for an ApiClient.
 * <p>
 * Determines where to get the JWKSet from based on the TrustedDirectory configuration.
 * - If the directory is configured to contain the JWKS in the SSA then it is fetched from here
 * - Otherwise we expect a jwks_uri to be configured, in which case a {@link JwkSetService} is used to obtain the JWKSet
 */
public class DefaultApiClientJwkSetService implements ApiClientJwkSetService {

    /**
     * The service to delegate to when looking up remote JWKSets by URI
     */
    private final JwkSetService jwkSetService;

    public DefaultApiClientJwkSetService(JwkSetService jwkSetService) {
        Reject.ifNull(jwkSetService, "jwkSetService must be provided");
        this.jwkSetService = jwkSetService;
    }

    /**
     * The JWKSet for an ApiClient can either be looked up via a URI or it is embedded into the software statement,
     * use the TrustedDirectory configuration to determine the location of the JWKSet.
     */
    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(ApiClient apiClient, TrustedDirectory trustedDirectory) {
        Reject.ifNull(apiClient, "apiClient must be provided");
        Reject.ifNull(trustedDirectory, "trustedDirectory must be provided");
        if (trustedDirectory.softwareStatementHoldsJwksUri()) {
            return getJwkSetUsingJwksUri(apiClient);
        } else {
            return getJwkSetFromSsaClaim(apiClient, trustedDirectory);
        }
    }

    /**
     * Use the jwkSetService to fetch the JWKSet using the ApiClient.jwksUri
     */
    private Promise<JWKSet, FailedToLoadJWKException> getJwkSetUsingJwksUri(ApiClient apiClient) {
        if (apiClient.getJwksUri() == null) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("TrustedDirectory configuration " +
                    "requires the jwksUri to be set for the apiClient"));
        }
        return jwkSetService.getJwkSet(apiClient.getJwksUri());
    }

    /**
     * Extract the JWKSet from a claim within the software statement assertion.
     */
    private Promise<JWKSet, FailedToLoadJWKException> getJwkSetFromSsaClaim(ApiClient apiClient, TrustedDirectory trustedDirectory) {
        final String jwksClaimsName = trustedDirectory.getSoftwareStatementJwksClaimName();
        if (jwksClaimsName == null) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("Trusted Directory has " +
                    "softwareStatemdntHoldsJwksUri=false but is missing softwareStatementJwksClaimName value"));
        }
        final JsonValue rawJwks = apiClient.getSoftwareStatementAssertion().getClaimsSet().get(jwksClaimsName);
        if (rawJwks.isNull()) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("SSA is missing claim: " + jwksClaimsName
                    + " which is expected to contain the JWKS"));
        }
        try {
            return Promises.newResultPromise(JWKSet.parse(rawJwks));
        } catch (JsonException je) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("Invalid JWKS json at claim: " + jwksClaimsName, je));
        }
    }
}
