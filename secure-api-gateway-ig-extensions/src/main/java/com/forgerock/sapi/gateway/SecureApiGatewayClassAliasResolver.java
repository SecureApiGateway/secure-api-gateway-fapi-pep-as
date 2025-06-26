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
package com.forgerock.sapi.gateway;

import java.util.HashMap;
import java.util.Map;

import org.forgerock.openig.alias.ClassAliasResolver;

import com.forgerock.sapi.gateway.am.AccessTokenResponseIdTokenReSignFilter;
import com.forgerock.sapi.gateway.am.AuthorizeResponseJwtReSignFilter;
import com.forgerock.sapi.gateway.am.JwtReSigner;
import com.forgerock.sapi.gateway.common.exception.SapiLogAttachedExceptionFilterHeaplet;
import com.forgerock.sapi.gateway.consent.ConsentRequestAccessAuthorisationFilter;

public class SecureApiGatewayClassAliasResolver implements ClassAliasResolver {
    private static final Map<String, Class<?>> ALIASES = new HashMap<>();

    static {
        ALIASES.put("ConsentRequestAccessAuthorisationFilter", ConsentRequestAccessAuthorisationFilter.class);
        ALIASES.put("SapiLogAttachedExceptionFilter", SapiLogAttachedExceptionFilterHeaplet.class);
        ALIASES.put("JwtReSigner", JwtReSigner.class);
        ALIASES.put("AccessTokenResponseIdTokenReSignFilter", AccessTokenResponseIdTokenReSignFilter.class);
        ALIASES.put("AuthorizeResponseJwtReSignFilter", AuthorizeResponseJwtReSignFilter.class);
    }

    /**
     * Get the class for a short name alias.
     *
     * @param alias Short name alias.
     * @return      The class, or null if the alias is not defined.
     */
    @Override
    public Class<?> resolve(final String alias) {
        return ALIASES.get(alias);
    }
}
