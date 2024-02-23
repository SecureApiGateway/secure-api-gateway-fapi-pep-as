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

import java.security.SignatureException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;

/**
 * Class that provides validation of registration request JWTs. It handles both those that need to be validated
 * using a JWKS embedded in the Software Statement and those that have a JWKS URI in the software statement
 *
 * For an overview of how this class works see:
 * <a href="https://github.com/SecureApiGateway/SecureApiGateway/wiki/About-Dynamic-Client-Registration">
 *     About Dynamic Client Registration</a>
 */
public class RegistrationRequestJwtSignatureValidationService {
    private static final Logger log = LoggerFactory.getLogger(RegistrationRequestJwtSignatureValidationService.class);
    private final JwksSupplierEmbeddedJwks jwksSignatureValidator;
    private final JwksSupplierJwksUri jwksUriSignatureValidator;
    private final JwtSignatureValidator jwtSignatureValidator;

    /**
     * Constructor
     * @param jwksSignatureValidator the service used to validate a jwk against a jwks
     * @param jwksUriSignatureValidator the service used to validate a jwk against a jwks_uri
     */
    public RegistrationRequestJwtSignatureValidationService(
            JwksSupplierEmbeddedJwks jwksSignatureValidator,
            JwksSupplierJwksUri jwksUriSignatureValidator,
            JwtSignatureValidator jwtSignatureValidator) {
        this.jwksSignatureValidator = jwksSignatureValidator;
        this.jwksUriSignatureValidator = jwksUriSignatureValidator;
        this.jwtSignatureValidator = jwtSignatureValidator;
    }

    /**
     * Validate a registration request signature
     * @param registrationRequest the registration request to be validated
     * @return A Promise containing a Response (OK), or a DCRSignatureValidationException explaining why the
     * registration request signature validation failed
     */
    public Promise<Response, DCRSignatureValidationException> validateJwtSignature(RegistrationRequest registrationRequest) {
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();

        JwksSupplier supplier;
        if (softwareStatement.hasJwksUri()) {
            log.debug("SSA contains JwksUri - using the JwksUri Validator");
            supplier = jwksUriSignatureValidator;
        } else {
            log.debug("SSA contains an inline JWKS - using the Jwks Validator");
            supplier = jwksSignatureValidator;
        }

        return supplier.getJWKSet(registrationRequest).thenAsync((jwks)->{
            try {
                log.debug("Validating jwt signed by {} against jwks {}", registrationRequest.getKeyId(), jwks);
                jwtSignatureValidator.validateSignature(registrationRequest.getSignedJwt(), jwks);
                return Promises.newResultPromise(new Response(Status.OK));
            } catch (SignatureException e) {
                String errorDescription = "Registration Request signature is invalid: '" + e.getMessage() + "'";
                log.info(errorDescription, e);
                return Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription));
            }
        }, failedToLoadJwksException -> {
            String errorDescription = "Failed to get JWKSet from '" + softwareStatement.getJwksUri().toString() + "'";
            return Promises.newExceptionPromise(
                    new DCRSignatureValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription));
        });
    }
}
