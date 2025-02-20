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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Class used to sign a jwt using an RSASASigner initialized with a newly created RSA private key
 */
public class JWTSigner {
    private final RSASSASigner jwtSigner = new RSASSASigner(CryptoUtils.generateRsaKeyPair().getPrivate());

    /**
     * Creates a Signed JWT in the JWS Compact Serialisation format
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.1">here</a>
     * @param claimsSet the claims to be included in the signed jwt
     * @return a JWS Compact Serialized signed JWT
     * @throws JOSEException when the jwt can't be signed
     */
    String createSignedRequestJwt(JWTClaimsSet claimsSet) throws JOSEException {
        final SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.PS256).keyID("test-kid").build(), claimsSet);
        signedJWT.sign(jwtSigner);
        return signedJWT.serialize();
    }
}
