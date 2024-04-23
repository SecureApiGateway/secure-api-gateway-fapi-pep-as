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
package com.forgerock.sapi.gateway.jwks.cache;

import java.net.URI;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.jwks.JwkSetService;

/**
 * CachingJwkSetService provides an implementation of {@link JwkSetService} which caches JWKSet data.
 * <p>
 * This implementation delegates to an underlying instance of JwkSetService to fetch the actual data. The data is
 * then stored in a pluggable {@link Cache} implementation.
 * <p>
 * The Cache implementation should manage eviction as required, this class will only invalidate entries in the case where
 * a new key may have been added to a cache JWKSet i.e. the JWKSet is found in the cache but it does not contain the keyId.
 */
public class CachingJwkSetService implements JwkSetService {

    private static final Logger logger = LoggerFactory.getLogger(CachingJwkSetService.class);
    private final JwkSetService underlyingJwkSetService;
    private final Cache<URI, JWKSet> jwkSetCache;

    public CachingJwkSetService(JwkSetService underlyingJwkSetService, Cache<URI, JWKSet> jwkSetCache) {
        Reject.ifNull(underlyingJwkSetService, "underlyingJwkSetService must be supplied");
        Reject.ifNull(jwkSetCache, "jwkSetCache implementation must be supplied");
        this.underlyingJwkSetService = underlyingJwkSetService;
        this.jwkSetCache = jwkSetCache;
    }

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkSetUri) {
        if (jwkSetUri == null) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("jwkSetUri is null"));
        }
        final JWKSet cachedJwkSet = jwkSetCache.get(jwkSetUri);
        if (cachedJwkSet == null) {
            return underlyingJwkSetService.getJwkSet(jwkSetUri).thenOnResult(jwkSet -> {
                logger.debug("Fetched jwkStore from uri: {}", jwkSetUri);
                jwkSetCache.put(jwkSetUri, jwkSet);
            });
        } else {
            logger.info("Found jwkStore in cache, for uri: {}", jwkSetUri);
            return Promises.newResultPromise(cachedJwkSet);
        }
    }

    @Override
    public Promise<JWK, FailedToLoadJWKException> getJwk(URI jwkSetUri, String keyId) {
        if (keyId == null) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("keyId is null"));
        }
        return getJwkSet(jwkSetUri).thenAsync(jwkSetResultHandler(jwkSetUri, keyId));
    }

    private AsyncFunction<JWKSet, JWK, FailedToLoadJWKException> jwkSetResultHandler(URI jwksSetUri, String keyId) {
        return jwkSet -> {
            JWK jwk = jwkSet.findJwk(keyId);
            if (jwk != null) {
                return Promises.newResultPromise(jwk);
            } else {
                logger.debug("keyId: {} not found in cached JWKSet for uri: {}, " +
                        "invalidating and fetching JWKSet from uri again", keyId, jwksSetUri);
                // JWKSet exists but key not in set, new key may have been added to set since it was cached, fetch it again
                jwkSetCache.invalidate(jwksSetUri);
                return getJwkSet(jwksSetUri).then(JwkSetService.findJwkByKeyId(keyId));
            }
        };
    }
}
