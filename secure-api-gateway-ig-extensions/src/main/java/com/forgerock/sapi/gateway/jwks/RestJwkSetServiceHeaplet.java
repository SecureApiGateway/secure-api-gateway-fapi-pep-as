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

import static org.forgerock.openig.heap.Keys.CLIENT_HANDLER_HEAP_KEY;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.json.jose.jwk.JWKSetParser;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;

/**
 * Creates a RestJwkSetService
 * <p>
 * Accepts a handler configuration, defaulting to the default ClientHandler if this is not specified.
 */
public class RestJwkSetServiceHeaplet extends GenericHeaplet {
    @Override
    public Object create() throws HeapException {
        return createRestJwkSetService();
    }

    protected RestJwkSetService createRestJwkSetService() throws HeapException {
        final JWKSetParser jwkSetParser = createJWKSetParser();
        return new RestJwkSetService(jwkSetParser);
    }

    private JWKSetParser createJWKSetParser() throws HeapException {
        final Handler handler = getHandler();
        final Client httpClient = new Client(handler);
        return new JWKSetParser(httpClient);
    }

    /**
     * Gets the Handler to use for the {@link Client} used to make the http calls to fetch JWKS data.
     * Defaults to the default ClientHandler as per CLIENT_HANDLER_HEAP_KEY
     */
    private Handler getHandler() throws HeapException {
        return config.get("handler").defaultTo(CLIENT_HANDLER_HEAP_KEY).as(requiredHeapObject(heap, Handler.class));
    }
}
