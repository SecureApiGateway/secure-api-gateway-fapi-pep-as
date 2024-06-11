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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Objects;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.JWKSetParser;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * JwkSetService which fetches JWKSet data from a REST endpoint, implementation is delegated to {@link JWKSetParser}
 */
public class RestJwkSetService implements JwkSetService {

    private final JWKSetParser jwkSetParser;

    public RestJwkSetService(JWKSetParser jwkSetParser) {
        this.jwkSetParser = jwkSetParser;
    }

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URI jwkSetUri) {
        try {
            final URL jwkSetUrl = Objects.requireNonNull(jwkSetUri, "jwkSetUri cannot be null").toURL();
            return jwkSetParser.jwkSetAsync(jwkSetUrl);
        } catch (MalformedURLException e) {
            return Promises.newExceptionPromise(new FailedToLoadJWKException("jwksSetUri is not a valid URL", e));
        }

    }

    @Override
    public Promise<JWK, FailedToLoadJWKException> getJwk(URI jwkSetUri, String keyId) {
        return getJwkSet(jwkSetUri).then(JwkSetService.findJwkByKeyId(keyId));
    }

}
