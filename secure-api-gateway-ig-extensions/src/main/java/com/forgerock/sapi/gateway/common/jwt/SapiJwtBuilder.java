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
package com.forgerock.sapi.gateway.common.jwt;

import org.apache.ivy.util.StringUtils;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;

import com.forgerock.sapi.gateway.jws.JwtDecoder;

/**
 * Parent of Builder classes that build the SoftwareStatement and the RegistrationRequest.
 * The base class holds a {@code JwtDecoder} and provides common methods that can be used to initalise the common
 * fields like kid, issuer, claimsSet etc.
 */
public abstract class SapiJwtBuilder {

    protected final JwtDecoder jwtDecoder;
    protected String b64EncodedJwtString;
    protected SignedJwt signedJwt;
    protected String kid;
    protected ClaimsSetFacade claimsSet;
    protected String issuer;

    /**
     * Constructor
     *
     * @param jwtDecoder used to decode the b64 url encoded jwt string into a {@code SignedJwt} representation.
     *                   Must not be null.
     */
    public SapiJwtBuilder(JwtDecoder jwtDecoder) {
        Reject.ifNull(jwtDecoder, "jwtDecoder must not be null");
        this.jwtDecoder = jwtDecoder;
    }

    public String getB64EncodedJwtString() {
        return b64EncodedJwtString;
    }

    public String getKid() {
        return kid;
    }

    public ClaimsSetFacade getClaimsSet() {
        return claimsSet;
    }

    public String getIssuer() {
        return issuer;
    }

    /**
     * @return a {@code SignedJwt} representation of the b64 url encoded jwt string.
     */
    public SignedJwt getSignedJwt() {
        return signedJwt;
    }

    /**
     * Parses the b64 url encoded representation of jwt into a SignedJwt representation, gets the claims from the jwt,
     * and sets the kid, and issuer fields from the header and the claims.
     *
     * @param b64EncodedJwtString the b64 url encoded representation of the jwt
     * @throws JwtException when the jwt can't be processed or does not contain required fields
     */
    protected void buildBaseJwt(String b64EncodedJwtString) throws JwtException {
        Reject.ifNull(b64EncodedJwtString, "b64EncodedJwtString must not be null");
        this.b64EncodedJwtString = b64EncodedJwtString;
        this.signedJwt = jwtDecoder.getSignedJwt(b64EncodedJwtString);
        this.kid = getKeyIdFromSignedJwt(this.signedJwt);
        this.claimsSet = new ClaimsSetFacade(signedJwt.getClaimsSet());
        this.issuer = claimsSet.getIssuer();
    }

    /**
     * Get the keyId from the header
     *
     * @param signedJwt the signed jwt to obtain the keyId from
     * @return the keyId
     * @throws JwtException throws if the jwt has no header, or has no valid keyId
     */
    private String getKeyIdFromSignedJwt(SignedJwt signedJwt) throws JwtException {
        JwsHeader header = signedJwt.getHeader();
        if (header == null) {
            throw new JwtException("Jwt must have a header");
        }
        String kid = header.getKeyId();
        if (StringUtils.isNullOrEmpty(kid)) {
            throw new JwtException("Jwt header must contain a 'kid' claim");
        }
        return kid;
    }


}
