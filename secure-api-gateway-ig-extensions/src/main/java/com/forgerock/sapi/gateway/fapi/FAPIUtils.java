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
package com.forgerock.sapi.gateway.fapi;

import java.util.Optional;

import org.forgerock.http.protocol.Request;
import org.forgerock.util.Reject;

public class FAPIUtils {

    public static final String X_FAPI_INTERACTION_ID = "x-fapi-interaction-id";

    public static Optional<String> getFapiInteractionId(Request request) {
        Reject.ifNull(request);
        return Optional.ofNullable(request.getHeaders().getFirst(X_FAPI_INTERACTION_ID));
    }
}
