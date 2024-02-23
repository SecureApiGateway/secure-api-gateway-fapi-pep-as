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

import java.net.URL;

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
    private final Cache<URL, JWKSet> jwkSetCache;

    public CachingJwkSetService(JwkSetService underlyingJwkSetService, Cache<URL, JWKSet> jwkSetCache) {
        Reject.ifNull(underlyingJwkSetService, "underlyingJwkSetService must be supplied");
        Reject.ifNull(jwkSetCache, "jwkSetCache implementation must be supplied");
        this.underlyingJwkSetService = underlyingJwkSetService;
        this.jwkSetCache = jwkSetCache;
    }

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URL jwkStoreUrl) {
        if (jwkStoreUrl == null) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("jwkStoreUrl is null"));
        }
        final JWKSet cachedJwkSet = jwkSetCache.get(jwkStoreUrl);
        if (cachedJwkSet == null) {
            return underlyingJwkSetService.getJwkSet(jwkStoreUrl).thenOnResult(jwkSet -> {
                logger.debug("Fetched jwkStore from url: {}", jwkStoreUrl);
                jwkSetCache.put(jwkStoreUrl, jwkSet);
            });
        } else {
            logger.info("Found jwkStore in cache, for url: {}", jwkStoreUrl);
            return Promises.newResultPromise(cachedJwkSet);
        }
    }

    @Override
    public Promise<JWK, FailedToLoadJWKException> getJwk(URL jwkStoreUrl, String keyId) {
        if (keyId == null) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("keyId is null"));
        }
        return getJwkSet(jwkStoreUrl).thenAsync(jwkSetResultHandler(jwkStoreUrl, keyId));
    }

    private AsyncFunction<JWKSet, JWK, FailedToLoadJWKException> jwkSetResultHandler(URL jwkStoreUrl, String keyId) {
        return jwkSet -> {
            JWK jwk = jwkSet.findJwk(keyId);
            if (jwk != null) {
                return Promises.newResultPromise(jwk);
            } else {
                logger.debug("keyId: {} not found in cached JWKSet for url: {}, invalidating and fetching JWKSet from url again", keyId, jwkStoreUrl);
                // JWKSet exists but key not in set, new key may have been added to set since it was cached, fetch it again
                jwkSetCache.invalidate(jwkStoreUrl);
                return getJwkSet(jwkStoreUrl).then(JwkSetService.findJwkByKeyId(keyId));
            }
        };
    }
}
