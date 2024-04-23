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
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import java.net.URI;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jwks.JwkSetService;

/**
 * Class used to obtain a JWKSet from a JWKS Uri
 */
public class JwksSupplierJwksUri implements JwksSupplier {

    private static final Logger log = LoggerFactory.getLogger(JwksSupplierJwksUri.class);
    private final JwkSetService jwkSetService;

    /**
     * Constructor
     * @param jwkSetService a service that gets the JWKS from a JWKS URI
     */
    public JwksSupplierJwksUri(JwkSetService jwkSetService) {
        this.jwkSetService = jwkSetService;
    }

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJWKSet(RegistrationRequest registrationRequest) {
            SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
            URI softwareStatementsJwksUri = softwareStatement.getJwksUri();
            log.debug("Using the jwkSetService to obtain a JWKSet from '{}'", softwareStatementsJwksUri);
            return jwkSetService.getJwkSet(softwareStatementsJwksUri);
    }
}
