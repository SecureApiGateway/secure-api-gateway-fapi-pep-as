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

import java.net.URI;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.Function;
import org.forgerock.util.promise.Promise;

/**
 * Service which can retrieve JWKSet and JWK objects
 */
public interface JwkSetService {

    /**
     * Creates a helper function which locates a JWK in a JWKSet using the keyId (kid)
     *
     * @param keyId String the kid value of the JWK to match
     * @return Function which takes as input a JWKSet and returns the JWK with matching keyId, if no match can be found
     * then a FailedToLoadJWKException is thrown
     */
    static Function<JWKSet, JWK, FailedToLoadJWKException> findJwkByKeyId(String keyId) {
        return jwkSet -> {
            final JWK jwk = jwkSet.findJwk(keyId);
            if (jwk != null) {
                return jwk;
            } else {
                throw new FailedToLoadJWKException("Failed to find keyId: " + keyId + " in JWKSet");
            }
        };
    }

    /**
     * Retrieves a JWKSet for the specified uri
     *
     * @param jwkSetUri uri used to locate the JWKSet
     * @return Promise which either returns a non-null JWKSet or fails with a FailedToLoadJWKException
     */
    Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkSetUri);

    /**
     * Retrieves a JWK with the specified keyId from the JWKSet at the specified uri.
     *
     * @param jwkSetUri uri used to locate the JWKSet
     * @param keyId the id (kid) of the JWK within the store to return
     * @return Promise which either returns a non-null JWK or fails with a FailedToLoadJWKException
     */
    Promise<JWK, FailedToLoadJWKException> getJwk(URI jwkSetUri, String keyId);

}
