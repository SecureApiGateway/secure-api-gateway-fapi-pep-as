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
package com.forgerock.sapi.gateway.jwks.cache.caffeine;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;

import org.assertj.core.api.Assertions;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.Pair;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceTest;
import com.forgerock.sapi.gateway.jwks.cache.BaseCachingJwkSetServiceTest;
import com.forgerock.sapi.gateway.jwks.cache.Cache;

class CaffeineCachingJwkSetServiceTest extends BaseCachingJwkSetServiceTest {
    @Override
    protected Cache<URI, JWKSet> createSimpleCache() {
        // Cache won't evict anything when the base test cases are run.
        return CaffeineCacheTest.createCacheNoTimeExpiry(1_000_000L);
    }

    @Test
    void shouldLimitCacheSize() throws Exception {
        final int cacheSize = 75;
        final CaffeineCache<URI, JWKSet> cache = CaffeineCacheTest.createCacheNoTimeExpiry(cacheSize);

        // jwks urls of the form: "http://jwks/$jwksId", each store contains one JWK with keyId of the form: "kid$jwksId"
        final IntFunction<String> jwksIdToKid = jwksId -> "kid" + jwksId;
        final IntFunction<Pair<URI, String>> jwksIdToUrlAndKid = jwksId -> Pair.of(URI.create("http://jwks/" + jwksId), jwksIdToKid.apply(jwksId));

        final AtomicInteger underlyingJwkSetGetJwkSetCount = new AtomicInteger();
        final CaffeineCachingJwkSetService jwkSetService = new CaffeineCachingJwkSetService(new BaseCachingTestJwkSetService() {
            @Override
            public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkSetUri) {
                underlyingJwkSetGetJwkSetCount.incrementAndGet();
                final String url = jwkSetUri.toString();
                final int lastSlashIndex = url.lastIndexOf('/');
                final String jwksId = url.substring(lastSlashIndex + 1);
                final String keyId = jwksIdToKid.apply(Integer.parseInt(jwksId));
                final JWKSet jwkSet = new JWKSet(RestJwkSetServiceTest.createJWK(keyId));
                return Promises.newResultPromise(jwkSet);
            }
        }, cache);

        final int numRequestsToMake = 5000;
        final int numUniqueJwks = 100; // larger than cacheSize
        final Random random = new Random();
        for (int request = 0; request < numRequestsToMake; request++) {
            final int jwksId = random.nextInt(numUniqueJwks);
            final Pair<URI, String> uriAndKid = jwksIdToUrlAndKid.apply(jwksId);
            final Promise<JWK, FailedToLoadJWKException> jwk = jwkSetService.getJwk(uriAndKid.getFirst(), uriAndKid.getSecond());
            assertEquals(uriAndKid.getSecond(), jwk.get().getKeyId());
        }

        // the underlying calls represent the cache misses, we will have at least the number of unique items
        Assertions.assertThat(underlyingJwkSetGetJwkSetCount.get()).isGreaterThanOrEqualTo(numUniqueJwks);
        // verify that we go some items from the cache
        Assertions.assertThat(underlyingJwkSetGetJwkSetCount.get()).isLessThan(numRequestsToMake);
    }
}
