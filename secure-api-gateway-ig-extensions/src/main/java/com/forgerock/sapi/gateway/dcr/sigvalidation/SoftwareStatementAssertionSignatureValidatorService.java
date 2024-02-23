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

import java.net.URL;
import java.security.SignatureException;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.jws.JwtSignatureValidator;

/**
 * Validates the Signature of the software statement jwt.
 */
public class SoftwareStatementAssertionSignatureValidatorService {

    private static final Logger log = LoggerFactory.getLogger(SoftwareStatementAssertionSignatureValidatorService.class);
    private final JwkSetService jwkSetService;
    private final JwtSignatureValidator jwtSignatureValidator;


    /**
     * Constructs a DCRSsaValidator
     * @param jwkSetService obtains a JWK Set from a url (may provide caching)
     * @param jwtSignatureValidator validates the Software Statement Assertion's signature against a JWK Set
     */
    public SoftwareStatementAssertionSignatureValidatorService(JwkSetService jwkSetService,
            JwtSignatureValidator jwtSignatureValidator) {
        Reject.ifNull(jwkSetService, "jwkSetService must be provided");
        Reject.ifNull(jwtSignatureValidator, "jwtSignatureValidator must be provided");
        this.jwkSetService = jwkSetService;
        this.jwtSignatureValidator = jwtSignatureValidator;
    }

    /**
     * validates a Software Statement Assertion's signature. A Software Statement Assertion is a signed JWT issued
     * by a Trusted Directory. It's signature must be validated against a JWK Set hosted by the issuing trusted
     * directory
     *
     * @param softwareStatement the Software Statement Assertion to be validated
     * @return a Promise containing a Response with status 200 (Status.OK) or a DCRSignatureValidationException
     * containing information regarding the reason that the Software Statement Assertion could not be validated
     */
    public Promise<Response, DCRSignatureValidationException> validateJwtSignature(SoftwareStatement softwareStatement) {
        Reject.ifNull(softwareStatement, "softwareStatement must be provided");
        try {

            URL issuingDirectoryJwksUrl = softwareStatement.getTrustedDirectoryJwksUrl();
            return this.jwkSetService.getJwkSet(issuingDirectoryJwksUrl).thenAsync(directoryJwkSet -> {
                try {
                    this.jwtSignatureValidator.validateSignature(softwareStatement.getSignedJwt(), directoryJwkSet);
                    log.debug("SSA has a valid signature");
                    softwareStatement.setSignatureHasBeenValidated(true);
                    return Promises.newResultPromise(new Response(Status.OK));
                } catch (SignatureException e) {
                    String errorDescription = "Failed to validate SSA against jwks_uri '" + issuingDirectoryJwksUrl +
                            "'";
                    log.debug(errorDescription);
                    return Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription));
                }
            }, ex -> {
                String errorDescription = "Failed to obtain jwk set from trusted directory uri " + issuingDirectoryJwksUrl;
                log.debug(errorDescription, ex);
                return Promises.newExceptionPromise(
                        new DCRSignatureValidationException(DCRErrorCode.INVALID_SOFTWARE_STATEMENT, errorDescription));
            });
        }  catch (RuntimeException rte){
            return Promises.newRuntimeExceptionPromise(rte);
        }
    }
}
