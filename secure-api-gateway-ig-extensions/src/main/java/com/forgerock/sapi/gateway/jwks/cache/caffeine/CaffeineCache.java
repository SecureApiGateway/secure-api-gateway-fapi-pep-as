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

import java.time.Duration;
import java.util.concurrent.Executor;

import com.forgerock.sapi.gateway.jwks.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Implementation of {@link Cache} which delegates to {@link com.github.benmanes.caffeine.cache.Cache}
 */
public class CaffeineCache<K, V> implements Cache<K, V> {

    public static class CacheOptions {
        private final Caffeine builder = Caffeine.newBuilder();

        public CacheOptions maximumCacheEntries(long maximumSize) {
            builder.maximumSize(maximumSize);
            return this;
        }

        public CacheOptions expireAfterWrite(Duration duration) {
            builder.expireAfterWrite(duration);
            return this;
        }

        public CacheOptions executor(Executor executor) {
            builder.executor(executor);
            return this;
        }

        private com.github.benmanes.caffeine.cache.Cache build() {
            return builder.build();
        }

        @Override
        public String toString() {
            return "CacheOptions{" +
                    "builder=" + builder +
                    '}';
        }
    }

    private final com.github.benmanes.caffeine.cache.Cache<K, V> cache;

    public CaffeineCache(CacheOptions options) {
        cache = options.build();
    }

    @Override
    public V get(K key) {
        return cache.getIfPresent(key);
    }

    @Override
    public void put(K key, V value) {
        cache.put(key, value);
    }

    @Override
    public void invalidate(K key) {
        cache.invalidate(key);
    }
}
