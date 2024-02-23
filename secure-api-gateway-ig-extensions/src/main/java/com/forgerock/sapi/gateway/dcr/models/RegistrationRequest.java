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
package com.forgerock.sapi.gateway.dcr.models;

import java.net.URL;
import java.util.List;
import java.util.Optional;

import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.common.jwt.SapiJwt;
import com.forgerock.sapi.gateway.common.jwt.SapiJwtBuilder;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;

/**
 * The RegistrationRequest model that holds fields obtained from the b64 url encoded registration request jwt passed
 * to the /register endpoint as a part of a Dynamic Client Registration Request
 */
public class RegistrationRequest extends SapiJwt {

    /**
     * The key of the context attribute in which the dynamic client request object is stored.
     */
    public static final String REGISTRATION_REQUEST_KEY = "registrationRequest";

    private final SoftwareStatement softwareStatement;
    private final List<URL> redirectUris;

    public RegistrationRequest(Builder builder){
        super(builder);
        this.softwareStatement = builder.softwareStatement;
        this.redirectUris = builder.redirectUris;
    }

    public void setResponseTypes(List<String> responseTypes){
        this.getClaimsSet().setStringArrayClaim("response_types", responseTypes);
    }

    public Optional<List<String>> getResponseTypes(){
        try {
            return this.getClaimsSet().getOptionalStringListClaim("response_types");
        } catch (JwtException e) {
            return Optional.empty();
        }
    }

    /**
     * @return the {@code SoftwareStatement} representation of the Software Statement Assertion that was provided in the
     *         registration request
     */
    public SoftwareStatement getSoftwareStatement() {
        return softwareStatement;
    }

    /**
     * @return the redirect urls specified in the registration request
     */
    public List<URL> getRedirectUris(){
        return this.redirectUris;
    }

    /**
     * Class to build a {@code RegistrationRequest} from the b64 url encoded registration request jwt string.
     */
    public static class Builder extends SapiJwtBuilder {

        private static final Logger log = LoggerFactory.getLogger(Builder.class);
        private final SoftwareStatement.Builder softwareStatementBuilder;
        private SoftwareStatement softwareStatement;
        private List<URL> redirectUris;

        /**
         * Construct a {@code Builder)
         * @param softwareStatementBuilder a builder used to construct a {@code SoftwareStatement} from the b64 encoded
         * jwt string found in the 'software_statement' claim of the registration request as specified in
         * <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.1.1"> rfc7591, section 3.1.1</a>
         * @param jwtDecoder a class used to decode the b64 encoded 'short representation' of the registration request
         * into a SignedJwt representation
         */
        public Builder(SoftwareStatement.Builder softwareStatementBuilder, JwtDecoder jwtDecoder){
            super(jwtDecoder);
            Reject.ifNull(softwareStatementBuilder, "softwareStatementBuilder must not be null");
            this.softwareStatementBuilder = softwareStatementBuilder;
        }

        /**
         * Build a {@code RegistrationRequest} from the b64 encoded string representation of the registration request
         * jwt
         * @param b64EncodedJwtString the b64 encoded jwt string from the registration request body
         * @return a {@code RegistrationRequest} object
         * @throws DCRRegistrationRequestBuilderException when the {@code RegistrationRequest} can't be build because
         * the b64EncodedJwtString is malformed in some way or doesn't contain the expected claims
         */
        public RegistrationRequest build(String b64EncodedJwtString)
                throws DCRRegistrationRequestBuilderException {
            try {
                super.buildBaseJwt(b64EncodedJwtString);
                populateRegistrationRequest();
                return new RegistrationRequest(this);
            } catch (JwtException e) {
                String errorDescription = "Registration Request Jwt error: " + e.getMessage();
                log.debug(errorDescription, e);
                throw new DCRRegistrationRequestBuilderException(DCRErrorCode.INVALID_CLIENT_METADATA, errorDescription);
            }
        }

        private void populateRegistrationRequest()
                throws JwtException, DCRRegistrationRequestBuilderException {
            String SSA_CLAIM_NAME = "software_statement";
            String b64EncodedSsa = this.claimsSet.getStringClaim(SSA_CLAIM_NAME);
            softwareStatement = softwareStatementBuilder.build(b64EncodedSsa);
            this.redirectUris = this.claimsSet.getRequiredUriListClaim("redirect_uris");
        }

    }
}
