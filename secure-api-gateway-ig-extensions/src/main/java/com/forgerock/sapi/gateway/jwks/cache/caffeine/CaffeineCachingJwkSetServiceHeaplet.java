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
package com.forgerock.sapi.gateway.jwks.cache.caffeine;

import static org.forgerock.openig.util.JsonValues.javaDuration;

import java.net.URL;
import java.time.Duration;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.jwks.RestJwkSetService;
import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceHeaplet;
import com.forgerock.sapi.gateway.jwks.cache.CachingJwkSetService;
import com.forgerock.sapi.gateway.jwks.cache.caffeine.CaffeineCache.CacheOptions;

/**
 * Creates a {@link CachingJwkSetService} which is backed by a {@link CaffeineCache}
 * <p>
 * Delegates to {@link RestJwkSetServiceHeaplet} to create the {@link RestJwkSetService}, configuration for RestJwkSetService
 * will be honoured.
 */
public class CaffeineCachingJwkSetServiceHeaplet extends RestJwkSetServiceHeaplet {

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private static final long DEFAULT_MAX_CACHE_SIZE = 100L;
    /**
     * Represents a {@link org.forgerock.util.time.Duration}, an english representation of a duration.
     */
    private static final String DEFAULT_EXPIRE_AFTER_WRITE_DURATION = "5 minutes";

    @Override
    public Object create() throws HeapException {
        final RestJwkSetService restJwkSetService = createRestJwkSetService();
        return new CachingJwkSetService(restJwkSetService, createCaffeineCache());
    }

    private CaffeineCache<URL, JWKSet> createCaffeineCache() {
        final long maxCacheEntries = config.get("maxCacheEntries")
                .as(evaluatedWithHeapProperties())
                .defaultTo(DEFAULT_MAX_CACHE_SIZE)
                .asLong();
        final Duration expireAfterWrite = config.get("expireAfterWriteDuration")
                .as(evaluatedWithHeapProperties())
                .defaultTo(DEFAULT_EXPIRE_AFTER_WRITE_DURATION)
                .as(javaDuration());
        final CacheOptions options = new CacheOptions().maximumCacheEntries(maxCacheEntries)
                .expireAfterWrite(expireAfterWrite);
        logger.info("Creating a cache with options: {}", options);
        return new CaffeineCache<>(options);
    }
}
