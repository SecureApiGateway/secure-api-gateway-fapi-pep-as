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
package com.forgerock.sapi.gateway.jwt;

import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.Payload;

/**
 * Extension of {@link SignedJwt} supporting plain {@link String} nested payload.
 */
public class SignedJwtWithStringPayload extends SignedJwt {

    /**
     * Construct a {code StringBasedSignedJwt} from an existent one.
     * @param signedJwt the signed JWT
     */
    protected SignedJwtWithStringPayload(final SignedJwtWithStringPayload signedJwt) {
        super(signedJwt);
    }

    /**
     * Constructs a fresh, new SignedJwt from the given JwsHeader and nested Encrypted JWT.
     * <p>
     * The specified private key will be used in the creation of the JWS signature.
     *
     * @param header The JwsHeader containing the header parameters of the JWS.
     * @param nestedPayload The nested payload that will be the payload of this JWS.
     * @param signingHandler The SigningHandler instance used to sign the JWS.
     */
    public SignedJwtWithStringPayload(final JwsHeader header,
                                      final Payload nestedPayload,
                                      final SigningHandler signingHandler) {
        super(header, nestedPayload, signingHandler);
    }

    /**
     * Constructs a reconstructed SignedJwt from its constituent parts, the JwsHeader, nested Encrypted JWT, signing
     * input and signature.
     * <p>
     * For use when a signed nested encrypted JWT has been reconstructed from its base64url encoded string
     * representation and the signature needs verifying.
     *
     * @param header The JwsHeader containing the header parameters of the JWS.
     * @param nestedPayload The nested payload that is the payload of the JWS.
     * @param signingInput The original data that was signed, being the base64url encoding of the JWS header and
     *                     payload concatenated using a "." character.
     * @param signature The resulting signature of signing the signing input.
     */
    public SignedJwtWithStringPayload(final JwsHeader header,
                                      final Payload nestedPayload,
                                      final byte[] signingInput,
                                      final byte[] signature) {
        super(header, nestedPayload, signingInput, signature);
    }
}
