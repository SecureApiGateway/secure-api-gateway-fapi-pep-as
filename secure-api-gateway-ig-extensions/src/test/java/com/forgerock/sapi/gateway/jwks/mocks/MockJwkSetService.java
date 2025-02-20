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
package com.forgerock.sapi.gateway.jwks.mocks;

import java.net.URI;
import java.util.Map;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.forgerock.sapi.gateway.jwks.cache.BaseCachingJwkSetServiceTest;

/**
 * JwkSetService impl which returns a pre-canned JWKSet for an expectedJwkStoreUrl.
 * Returns an error if getJwkSet is called with a different url, or i getJwk is called.
 */
public class MockJwkSetService extends BaseCachingJwkSetServiceTest.BaseCachingTestJwkSetService {
    private final Map<URI, JWKSet> jwkSetsByUri;

    public MockJwkSetService(Map<URI, JWKSet> jwkSetsByURL) {
        this.jwkSetsByUri = jwkSetsByURL;
    }

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkStoreUri) {
        if (jwkSetsByUri.containsKey(jwkStoreUri)) {
            return Promises.newResultPromise(jwkSetsByUri.get(jwkStoreUri));
        }
        return Promises.newExceptionPromise(new FailedToLoadJWKException("actual jwkStoreUrl: " + jwkStoreUri
                + ", does not match expected: " + jwkSetsByUri.keySet()));

    }
}