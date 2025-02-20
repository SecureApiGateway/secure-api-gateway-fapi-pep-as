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
package com.forgerock.sapi.gateway.common.jwt;

import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;

/**
 * Base class that can be used to access common data held within a Json Web Token (JWT). This base class expects a
 * Jwt to have the following:
 * - a b64 url encoded string representation
 * - a SignedJwt representation
 * - a ClaimSetFacade allowing access to the Jwt's underlying Claims
 * - a kid claim (key Id) in the header
 * - an issuer claim
 */
public class SapiJwt {

    private final String b64EncodedJwtString;
    private final SignedJwt signedJwt;
    private final ClaimsSetFacade claimsSet;
    private final String keyId;
    private final String issuer;
    private boolean signatureHasBeenValidated;

    public SapiJwt(SapiJwtBuilder builder) {
        this.b64EncodedJwtString = builder.getB64EncodedJwtString();
        this.signedJwt = builder.getSignedJwt();
        this.claimsSet = builder.getClaimsSet();
        this.keyId = builder.getKid();
        this.issuer = builder.getIssuer();
        this.signatureHasBeenValidated = false;
        Reject.ifNull(issuer, "issuer must not be null");
        Reject.ifNull(keyId, "kid must not be null");
        Reject.ifNull(b64EncodedJwtString, "b64EncodedJwtString must not be null");
        Reject.ifNull(signedJwt, "signedJwt must not be null");
        Reject.ifNull(claimsSet, "claimsSet must not be null");
    }

    public boolean hasExpired() throws JwtException {
        return claimsSet.hasExpired();
    }

    /**
     * Indicates if the data in the Software Statement can be trusted, i.e. if the signature has been
     * validated against the relevant JWKS.
     * @return true if the software statement signature has been validated, false if it has not. Note that if this
     * method returns false it does not mean that the signature is invalid, mearly that it has not been validated. It
     * may be valid, but not have been validated.
     */
    public boolean signatureHasBeenValidated() {
        return signatureHasBeenValidated;
    }

    /**
     * Set a flag that indicates if the data in the Software Statement can be trusted, i.e. if the signature has been
     * validated against the relevant JWKS
     * @param signatureHasBeenValidated true if the signature has been validated, false if it has not.
     */
    public void setSignatureHasBeenValidated(boolean signatureHasBeenValidated) {
        this.signatureHasBeenValidated = signatureHasBeenValidated;
    }


    /**
     * @return the b64 url encoded string representation of the JWT
     */
    public String getB64EncodedJwtString() {
        return b64EncodedJwtString;
    }

    /**
     * @return the {@code SignedJwt} representation of the registration request
     */
    public SignedJwt getSignedJwt() {
        return signedJwt;
    }

    /**
     * @return the keyId, as found in the 'kid' claim in the jwt header
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * @return The the issuer of the jwt as found in the 'iss' claim
     */
    public String getIssuer() {
        return issuer;
    }


    /**
     * @return a string representation of the Jwt that includes the kid and an abbreviated b64 encoded jwt string
     */
    @Override
    public String toString() {
        String builder = "kid: '" + keyId + "'" + ", b64UrlEncoded JWT: '" +
                b64EncodedJwtString.substring(0, 6) + "..." +
                b64EncodedJwtString.substring((b64EncodedJwtString.length() - 7));
        return builder;
    }

    /**
     * @return the underlying ClaimsSetFacade that can be used to access the JwtClaims
     */
    public ClaimsSetFacade getClaimsSet() {
        return claimsSet;
    }
}
