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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.promise.Promises.newResultPromise;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This filter aims to fix an issue in AM relating to signing of the id_token JWTs returned by the /access_token
 * endpoint. The issue is that the wrong kid is used by AM, see {@link JwtReSigner} for further details.
 * <p>
 * id_token is optional, if one is present in the response then the {@link JwtReSigner} is used to re-sign it, otherwise
 * this filter does nothing.
 */
public class AccessTokenResponseIdTokenReSignFilter implements Filter {

    private static final String ID_TOKEN_FIELD_NAME = "id_token";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Takes a JWT as input, verifies the signature and re-signs it with the configured private key.
     */
    private final JwtReSigner jwtReSigner;

    public AccessTokenResponseIdTokenReSignFilter(JwtReSigner jwtReSigner) {
        Reject.ifNull(jwtReSigner, "jwtReSigner must be supplied");
        this.jwtReSigner = jwtReSigner;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        return handler.handle(context, request).thenAsync(response -> {
                    // Allow AM errors to pass through
                    if (!response.getStatus().isSuccessful()) {
                        return newResultPromise(response);
                    } else {
                        return response.getEntity().getJsonAsync().thenAsync(jsonObj -> {
                            logger.debug("Locating id_token in response json");
                            final JsonValue json = json(jsonObj);
                            final JsonValue idTokenValue = json.get(ID_TOKEN_FIELD_NAME);

                            // id_token is optional in the response - skip if not present
                            if (idTokenValue.isNull() || !idTokenValue.isString()) {
                                logger.debug("No id_token in response json - passing original response on");
                                return newResultPromise(response);
                            }
                            final String idToken = idTokenValue.asString();
                            return reSignIdTokenInResponse(response, json, idToken);
                        }, ex -> {
                            logger.error("Failed to re-sign id_token JWT", ex);
                            return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                        });

                    }
                });
    }

    private Promise<Response, NeverThrowsException> reSignIdTokenInResponse(Response response, JsonValue responseJson, String idToken) {
        return jwtReSigner.reSignJwt(idToken).then(reSignedIdToken -> {
            logger.debug("Successfully re-signed id_token: {} -> {}", idToken, reSignedIdToken);
            responseJson.put(ID_TOKEN_FIELD_NAME, reSignedIdToken);
            response.getEntity().setJson(responseJson);
            return response;
        }, ex -> {
            logger.error("Failed to re-sign id_token JWT", ex);
            return new Response(Status.INTERNAL_SERVER_ERROR);
        });
    }


    /**
     * Heaplet which creates {@link AccessTokenResponseIdTokenReSignFilter} objects.
     * <p>
     * Configuration:
     * <ul>
     *     <li>jwtReSigner name of a {@link JwtReSigner} available on the heap, used to validate in the incoming JWT
     *         and produce the new JWT signed with the correct key and keyId.</li>
     * </ul>
     * <p>
     * <pre>{@code
     * Example config:
     * {
     *   "name": "AccessTokenResponseIdTokenResignFilter",
     *   "type": "AccessTokenResponseIdTokenResignFilter",
     *   "comment": "Re-sign the id_token returned by AM (if present) to fix keyId issue"",
     *   "config": {
     *     "jwtReSigner": "jwtReSigner"
     *   }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final JwtReSigner jwtReSigner = config.get("jwtReSigner").as(requiredHeapObject(heap, JwtReSigner.class));
            return new AccessTokenResponseIdTokenReSignFilter(jwtReSigner);
        }
    }

}
