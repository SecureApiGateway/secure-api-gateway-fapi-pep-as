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

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;

/**
 * Class used to validate a registration request jwt signature against a JWKS embedded in the Software Statement
 */
public class JwksSupplierEmbeddedJwks implements JwksSupplier {

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJWKSet(RegistrationRequest registrationRequest) {
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        return Promises.newResultPromise(softwareStatement.getJwksSet());
    }
}
