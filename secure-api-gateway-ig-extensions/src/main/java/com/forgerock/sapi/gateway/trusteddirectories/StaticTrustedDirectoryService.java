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
package com.forgerock.sapi.gateway.trusteddirectories;

import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;
import static org.forgerock.json.JsonValueFunctions.listOf;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link TrustedDirectoryService} implementation that fetches {@link TrustedDirectory} configuration from static
 * collection of configurations.
 */
public class StaticTrustedDirectoryService implements TrustedDirectoryService {

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Map<String, TrustedDirectory> trustedDirectories;

    StaticTrustedDirectoryService(Map<String, TrustedDirectory> trustedDirectories) {
        if (trustedDirectories == null || trustedDirectories.isEmpty()) {
            throw new IllegalArgumentException("trustedDirectories configuration must not be null or empty");
        }
        this.trustedDirectories = Collections.unmodifiableMap(trustedDirectories);
    }

    @Override
    public TrustedDirectory getTrustedDirectoryConfiguration(String issuer) {
        final TrustedDirectory trustedDirectory = this.trustedDirectories.get(issuer);
        if (trustedDirectory != null && trustedDirectory.isDisabled()) {
            logger.warn("Failed to get TrustedDirectory configuration for issuer '{}', directory has been disabled", issuer);
            return null;
        }
        return trustedDirectory;
    }

    /**
     * Responsible for creating {@link StaticTrustedDirectoryService}
     * <p>
     * Mandatory config:
     * - trustedDirectories: array of {@link TrustedDirectory} definitions that the service supports
     * <pre>{@code
     * Example config:
     * {
     *      "name": "StaticTrustedDirectoryService",
     *      "type": "StaticTrustedDirectoryService",
     *      "comment": "TrustedDirectoryService that supports a static collection of TrustedDirectory objects defined in config",
     *      "config": {
     *        "trustedDirectories": [ TrustedDirectory reference, ... ]
     *      }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final List<TrustedDirectory> trustedDirectories = config.get("trustedDirectories")
                                                                    .required()
                                                                    .expect(List.class)
                                                                    .as(listOf(requiredHeapObject(heap,
                                                                                                  TrustedDirectory.class)));
            return new StaticTrustedDirectoryService(trustedDirectories.stream()
                                                                       .collect(toMap(TrustedDirectory::getIssuer,
                                                                                      identity())));
        }
    }
}
