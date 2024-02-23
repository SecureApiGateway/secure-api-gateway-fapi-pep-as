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

/**
 * Minimal cache representation which supports the caching operations required for JWKS caching.
 *
 * @param <K> key
 * @param <V> value
 */
public interface Cache<K, V> {

    /**
     * Retrieves a value from the cache for the supplied key or null if the key does not exist in the cache.
     *
     * @param key - the key to retrieve the value for
     * @return the cached value or null if the key does not exist in the cache.
     */
    V get(K key);

    /**
     * Adds a value to the cache for the supplied key, overwriting the existing value if the key already exists in the cache.
     *
     * @param key - the key to associate the value with
     * @param value - the value to cache
     */
    void put(K key, V value);

    /**
     * Removes a value from the cache
     *
     * @param key - the key of the item to remove.
     */
    void invalidate(K key);
}
