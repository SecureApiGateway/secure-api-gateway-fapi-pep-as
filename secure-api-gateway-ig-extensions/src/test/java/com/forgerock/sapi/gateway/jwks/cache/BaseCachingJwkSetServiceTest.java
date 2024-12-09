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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.fapi.jwks.JwkSetService;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.jwks.RestJwkSetServiceTest;

/**
 * Set of test cases which should pass regardless of the caching implementation is used.
 * <p>
 * Subclasses may extend from these cases and add additional tests which are cache implementation specific.
 */
public abstract class BaseCachingJwkSetServiceTest {

    /**
     * Subclasses must implement this method to supply the tests with a cache implementation to use.
     * <p>
     * The cache should be "simple", it should not invalidate keys based on time/size requirements of these tests, keys
     * should only be invalidated when the invalidate method is explicitly called by these tests.
     */
    protected abstract Cache<URI, JWKSet> createSimpleCache();

    /**
     * The CachingJwkSetService never calls getJwk on the wrapped JwkSetService, therefore we always want to
     * throw an exception if this is accidentally called.
     */
    public static abstract class BaseCachingTestJwkSetService implements JwkSetService {
        @Override
        public Promise<JWK, FailedToLoadJWKException> getJwk(URI jwkSetUri, String keyId) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("getJwk failed"));
        }
    }

    /**
     * Test JwkSetService impl which responds with exception when any of its methods are called.
     */
    public static class ReturnsErrorsJwkStore extends BaseCachingTestJwkSetService {
        @Override
        public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkStoreUri) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("getJwkSet failed"));
        }
    }

    @Test
    void shouldGetJwkSetFromCache() throws Exception {
        final Cache<URI, JWKSet> cache = createSimpleCache();
        final URI jwkStoreKey = URI.create("http://jwk_store/1234556789");
        final JWKSet expectedJwkSet = new JWKSet();
        cache.put(jwkStoreKey, expectedJwkSet);
        final JwkSetService brokenJwkStore = new ReturnsErrorsJwkStore();

        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(brokenJwkStore, cache);
        // NOTE: using reference equality, rather than .equals - as we want to check whether we get the expected object
        assertSame(expectedJwkSet, cachingJwkStore.getJwkSet(jwkStoreKey).get());
    }

    @Test
    void shouldFailToGetJwkSetIfUrlIsNull() {
        final FailedToLoadJWKException failedToLoadJWKException = assertThrows(FailedToLoadJWKException.class,
                () -> new CachingJwkSetService(new ReturnsErrorsJwkStore(),
                        createSimpleCache()).getJwkSet(null).getOrThrow());
        assertEquals("jwkSetUri is null", failedToLoadJWKException.getMessage());
    }

    @Test
    void shouldThrowExceptionIfNotInCacheAndNotInUnderlyingJwkStore() {
        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(new ReturnsErrorsJwkStore(), createSimpleCache());
        final FailedToLoadJWKException failedToLoadJWKException = assertThrows(FailedToLoadJWKException.class,
                () -> cachingJwkStore.getJwkSet(URI.create("http://blah")).getOrThrow());
        assertEquals("getJwkSet failed", failedToLoadJWKException.getMessage());
    }

    @Test
    void shouldFailIfNotInCacheAndUnderlyingJwkStoreThrowsException() {
        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(new ReturnsErrorsJwkStore(), createSimpleCache());
        FailedToLoadJWKException actualException = assertThrows(FailedToLoadJWKException.class,
                () -> cachingJwkStore.getJwkSet(URI.create("http://blah")).getOrThrow());
        assertSame("getJwkSet failed", actualException.getMessage());
    }

    @Test
    void shouldPullThroughIntoCache() throws Exception {
        final URI jwkStoreKey = URI.create("http://jwk_store/cvsdsfsgf");
        final JWKSet expectedJwkSet = new JWKSet();
        final AtomicInteger underlyingJwkStoreCalledCount = new AtomicInteger();
        final JwkSetService underlyingJwkStore = new BaseCachingTestJwkSetService() {
            @Override
            public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkStoreUri) {
                underlyingJwkStoreCalledCount.incrementAndGet();
                if (jwkStoreUri.equals(jwkStoreKey)) {
                    return Promises.newResultPromise(expectedJwkSet);
                } else {
                    return Promises.newResultPromise(new JWKSet());
                }
            }
        };

        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(underlyingJwkStore, createSimpleCache());
        for (int i = 0; i < 5; i++) {
            assertSame(expectedJwkSet, cachingJwkStore.getJwkSet(jwkStoreKey).get());
            // Underlying store should only be called once to initially populate the cache
            assertEquals(1, underlyingJwkStoreCalledCount.get());
        }
        assertNotSame(expectedJwkSet, cachingJwkStore.getJwkSet(URI.create("http://another_store/asfdafadfdasf")).get());
        assertEquals(2, underlyingJwkStoreCalledCount.get());
    }

    @Test
    void shouldFetchAgainIfCacheEntryInvalidated() throws Exception {
        final Cache<URI, JWKSet> cache = createSimpleCache();
        final URI jwkStoreKey = URI.create("http://jwk_store/cvsdsfsgf");
        final JWKSet initialJwkSet = new JWKSet();
        final JWKSet updatedJwkSet = new JWKSet();
        final AtomicReference<JWKSet> jwkSetToReturn = new AtomicReference<>();
        jwkSetToReturn.set(initialJwkSet);
        final AtomicInteger underlyingJwkStoreCalledCount = new AtomicInteger();
        final JwkSetService underlyingJwkStore = new BaseCachingTestJwkSetService() {
            @Override
            public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkStoreUri) {
                underlyingJwkStoreCalledCount.incrementAndGet();
                return Promises.newResultPromise(jwkSetToReturn.get());
            }
        };

        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(underlyingJwkStore, cache);
        for (int i = 0; i < 5; i++) {
            assertSame(initialJwkSet, cachingJwkStore.getJwkSet(jwkStoreKey).get());
            // Underlying store should only be called once to initially populate the cache
            assertEquals(1, underlyingJwkStoreCalledCount.get());
        }

        // Invalidate the cache & update the underlyingJwkStore to return the updated value
        cache.invalidate(jwkStoreKey);
        jwkSetToReturn.set(updatedJwkSet);
        for (int i = 0; i < 5; i++) {
            JWKSet actualJwkSet = cachingJwkStore.getJwkSet(jwkStoreKey).get();
            assertNotSame(initialJwkSet, actualJwkSet);
            assertSame(updatedJwkSet, actualJwkSet);
            assertEquals(2, underlyingJwkStoreCalledCount.get());
        }
    }

    @Test
    void shouldGetJwkFromCache() throws Exception {
        final Cache<URI, JWKSet> cache = createSimpleCache();
        final URI jwkStoreKey = URI.create("http://jwk_store/1234556789");
        final String expectedKeyId = "expectedKeyId";
        final String[] keyIds = {"k1", "dfsdfsdf", expectedKeyId, "anotherkeyid"};
        final JWKSet jwkSet = new JWKSet(Arrays.stream(keyIds).map(RestJwkSetServiceTest::createJWK).collect(Collectors.toList()));
        cache.put(jwkStoreKey, jwkSet);
        final JwkSetService brokenJwkStore = new ReturnsErrorsJwkStore();

        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(brokenJwkStore, cache);
        JWK jwk = cachingJwkStore.getJwk(jwkStoreKey, expectedKeyId).get();
        assertEquals(expectedKeyId, jwk.getKeyId());
    }

    @Test
    void shouldFetchJwkSetAgainIfKeyIdNotFoundNewKeyAddedToJwkSet() throws Exception {
        final Cache<URI, JWKSet> cache = createSimpleCache();
        final URI jwkStoreKey = URI.create("http://jwk_store/1234556789");
        final List<String> keyIds = List.of("k1", "dfsdfsdf", "anotherkeyid");
        final JWKSet initialJwkSet = new JWKSet(keyIds.stream().map(RestJwkSetServiceTest::createJWK).collect(Collectors.toList()));
        cache.put(jwkStoreKey, initialJwkSet);

        // New key is not in the initialJwtSet
        final String newKeyId = "newKeyId";
        final List<String> updatedKeyIds = new ArrayList<>(keyIds);
        updatedKeyIds.add(newKeyId);
        final JwkSetService jwkSetService = new BaseCachingTestJwkSetService() {
            @Override
            public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkStoreUri) {
                // New JwkSet containing newKeyId
                return Promises.newResultPromise(new JWKSet(updatedKeyIds.stream().map(RestJwkSetServiceTest::createJWK).collect(Collectors.toList())));
            }
        };

        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(jwkSetService, cache);
        JWK jwk = cachingJwkStore.getJwk(jwkStoreKey, newKeyId).get();
        assertEquals(newKeyId, jwk.getKeyId());
    }

    @Test
    void shouldThrowExceptionIfKeyIdNotFoundAfterFetchingJwkSetAgain() {
        final Cache<URI, JWKSet> cache = createSimpleCache();
        final URI jwkStoreKey = URI.create("http://jwk_store/1234556789");
        final List<String> keyIds = List.of("k1", "dfsdfsdf", "anotherkeyid");
        final JWKSet initialJwkSet = new JWKSet(keyIds.stream().map(RestJwkSetServiceTest::createJWK).collect(Collectors.toList()));
        cache.put(jwkStoreKey, initialJwkSet);

        final JwkSetService jwkSetService = new BaseCachingTestJwkSetService() {
            @Override
            public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkStoreUri) {
                // New JWKSet which contains the same JWKs as before
                return Promises.newResultPromise(new JWKSet(keyIds.stream().map(RestJwkSetServiceTest::createJWK).collect(Collectors.toList())));
            }
        };

        final String newKeyId = "newKeyId";
        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(jwkSetService, cache);
        final FailedToLoadJWKException failedToLoadJWKException = assertThrows(FailedToLoadJWKException.class,
                () -> cachingJwkStore.getJwk(jwkStoreKey, newKeyId).getOrThrow());
        assertEquals("Failed to find keyId: newKeyId in JWKSet", failedToLoadJWKException.getMessage());
    }

    @Test
    void shouldThrowExceptionIfKeyIdNotFoundAfterFetchingJwkSetAgainDueToJwkSetNotFound() {
        final Cache<URI, JWKSet> cache = createSimpleCache();
        final URI jwkStoreKey = URI.create("http://jwk_store/1234556789");
        final List<String> keyIds = List.of("k1", "dfsdfsdf", "anotherkeyid");
        final JWKSet initialJwkSet = new JWKSet(keyIds.stream().map(RestJwkSetServiceTest::createJWK).collect(Collectors.toList()));
        cache.put(jwkStoreKey, initialJwkSet);

        final JwkSetService jwkSetService = new ReturnsErrorsJwkStore();

        final String newKeyId = "newKeyId";
        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(jwkSetService, cache);
        final FailedToLoadJWKException failedToLoadJWKException = assertThrows(FailedToLoadJWKException.class,
                () -> cachingJwkStore.getJwk(jwkStoreKey, newKeyId).getOrThrow());
        assertEquals("getJwkSet failed", failedToLoadJWKException.getMessage());
    }

    @Test
    void shouldFailToGetJwkIfKeyIdIsNull() {
        final FailedToLoadJWKException failedToLoadJWKException = assertThrows(FailedToLoadJWKException.class,
                () -> new CachingJwkSetService(new ReturnsErrorsJwkStore(),
                        createSimpleCache()).getJwk(URI.create("http://jwk.com"), null).getOrThrow());
        assertEquals("keyId is null", failedToLoadJWKException.getMessage());
    }

    @Test
    void shouldFailWithExceptionIfJwkSetDoesNotExist() {
        final CachingJwkSetService cachingJwkStore = new CachingJwkSetService(new ReturnsErrorsJwkStore(), createSimpleCache());
        final FailedToLoadJWKException failedToLoadException = assertThrows(FailedToLoadJWKException.class,
                () -> cachingJwkStore.getJwk(URI.create("http://any_jwk_store"), "anyKeyId").getOrThrow());
        assertEquals("getJwkSet failed", failedToLoadException.getMessage());
    }

    @Test
    void shouldThrowExceptionIfGetJwkFailsDueToGetJwkSetException() {
        final CachingJwkSetService jwkSetService = new CachingJwkSetService(new ReturnsErrorsJwkStore(), createSimpleCache());
        FailedToLoadJWKException actualException = assertThrows(FailedToLoadJWKException.class,
                () -> jwkSetService.getJwk(URI.create("http://jwks_url"), "kid").getOrThrow());
        assertSame("getJwkSet failed", actualException.getMessage());
    }

}
