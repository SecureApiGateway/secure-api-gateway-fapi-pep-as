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
package com.forgerock.sapi.gateway.jws.signer;

import static org.forgerock.openig.secrets.SecretsProviderHeaplet.secretsProvider;

import java.util.ArrayList;
import java.util.Map;

import org.forgerock.json.jose.builders.JwsHeaderBuilder;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link JwsSigner} which produces signed Jws values in compact serialization form,
 * as per <a href='https://datatracker.ietf.org/doc/html/rfc7515#section-3.1'>JWS Compact Serialization</a>
 * <p>
 * Includes a Static class Heaplet definition used by IG
 * </p>
 */
public class CompactSerializationJwsSigner implements JwsSigner {

    private static final Logger logger = LoggerFactory.getLogger(CompactSerializationJwsSigner.class);
    private final SigningManager signingManager;
    private final Purpose<SigningKey> signingKeyPurpose;
    private final String algorithm;
    private final String kid;

    public CompactSerializationJwsSigner(
            SecretsProvider secretsProvider,
            String signingKeyId,
            String kid,
            String algorithm
    ) {
        this.signingManager = new SigningManager(secretsProvider);
        this.kid = kid;
        this.algorithm = algorithm;
        this.signingKeyPurpose = Purpose.purpose(signingKeyId, SigningKey.class);
    }

    /**
     * Compute the payload signature.
     * <p>
     *     Builds a JWT Header instance, a <a href='https://datatracker.ietf.org/doc/html/rfc7515#section-4'>JOSE Header</a> with the below header set:
     *     <ul>
     *         <li><em>typ</em>: automatically added, declares the encoded object as JWT {@code { "typ": "JWT" }}</li>
     *         <li><em>alg</em>: value from property <em>algorithm</em></li>
     *         <li><em>kid</em>: value from property <em>kid</em></li>
     *         <li><em>crit</em>: key set values from passed <em>criticalHeaders</em>, ignored if null or empty</li>
     *         <li>Extends the JOSE header adding the <em>criticalHeaders</em> passed, as header {@code { map.key: map.value }}, ignored if null or empty</li>
     *     </ul>
     * </p>
     * <p>
     *     Builds the JWS payload with the passed <em>payload</em>.
     * </p>
     * <p>
     *     Builds the JWS Signing input encoded as Base 64 URL with the JOSE Header and the JWS payload
     *     to compute the signature, and finally produce a base64url encoded UTF-8 parts of the JWS,
     *     in accordance with <a href='https://datatracker.ietf.org/doc/html/rfc7515#section-7.1'>JWS compact serialization</a>
     * </p>
     * @param payload         {@link Map} to be signed, <em>must not be null or empty.</em>
     * @param criticalHeaders {@link Map} of <a href='https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11'>critical header parameter</a>,
     *                                    <em>can be null or empty, will be ignored in these cases.</em>
     * @return a {@link Promise} of the resulting object
     * or a {@link JwsSignerException} thrown by the task if it fails.
     */
    @Override
    public Promise<String, JwsSignerException> sign(
            final Map<String, Object> payload,
            final Map<String, Object> criticalHeaders
    ) {
        if (payload == null || payload.isEmpty()) {
            String reason = buildErrorMessage(
                    JwsSignerException.class.getSimpleName(),
                    "The payload cannot be null"
            );
            logger.error(reason);
            return Promises.newExceptionPromise(new JwsSignerException(reason));
        }
        return signingManager.newSigningHandler(signingKeyPurpose)
                .then(signingHandler -> sign(signingHandler, payload, criticalHeaders),
                        nsse -> {
                            throw sapiJwsSignerException(nsse);
                        }
                );
    }

    private String sign(
            SigningHandler signingHandler,
            final Map<String, Object> payload,
            final Map<String, Object> criticalHeaders
    ) throws JwsSignerException {
        try {
            final JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(payload);

            JwsHeaderBuilder jwsHeaderBuilder = new JwtBuilderFactory()
                    .jws(signingHandler)
                    .headers()
                    .alg(JwsAlgorithm.parseAlgorithm(algorithm))
                    .kid(kid);

            addCriticalClaims(jwsHeaderBuilder, criticalHeaders);

            return jwsHeaderBuilder.done().claims(jwtClaimsSet).build();

        } catch (Exception e) {
            throw sapiJwsSignerException(e);
        }
    }

    private void addCriticalClaims(JwsHeaderBuilder jwsHeaderBuilder, final Map<String, Object> criticalHeaders) {
        if (!(criticalHeaders == null) && !criticalHeaders.isEmpty()) {
            jwsHeaderBuilder.crit(new ArrayList<>(criticalHeaders.keySet()));
            criticalHeaders.forEach(jwsHeaderBuilder::header);
        }
    }

    private JwsSignerException sapiJwsSignerException(Exception exception) {
        String reason = buildErrorMessage(exception.getClass().getSimpleName(), exception.getMessage());
        logger.error(reason, exception);
        return new JwsSignerException(reason, exception);
    }

    private String buildErrorMessage(String exceptionName, String reason) {
        return String.join(
                ": ",
                String.format("Compute signature %s", exceptionName),
                reason
        );
    }

    /**
     * Heaplet used to create {@link CompactSerializationJwsSigner} objects
     * <p/>
     * Mandatory fields:
     * <ul>
     *     <li>secretsProvider: The SecretsProvider object to query for the 'signingKeyId' in the keystore</li>
     *     <li>signingKeyId: The signing key id name to identify the private key in the keystore to sign a JWT</li>
     *     <li>kid: Key ID to build the JWT header, used to validate the signature via JWKs</li>
     *     <li>algorithm: The name of the algorithm to use to sign the JWT</li>
     * </ul>
     * Example config:
     * <pre>{@code
     * {
     *     "comment": "Default payload signer",
     *     "name": "CompactSerializationJwsSigner-RSASSA-PSS",
     *     "type": "com.forgerock.sapi.gateway.jwks.sign.CompactSerializationJwsSigner",
     *     "config": {
     *         "algorithm": "PS256",
     *         "signingKeyId": "jwt.signer",
     *         "kid": "&{ig.ob.aspsp.signing.kid}",
     *         "secretsProvider": "SecretsProvider-ASPSP"
     *     }
     * }
     * }</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final SecretsProvider secretsProvider = config.get("secretsProvider").required()
                    .as(secretsProvider(heap));
            final String signingKeyId = config.get("signingKeyId").required().asString();
            final String kid = config.get("kid").as(evaluatedWithHeapProperties()).required().asString();
            final String algorithm = config.get("algorithm").required().asString();
            return new CompactSerializationJwsSigner(secretsProvider, signingKeyId, kid, algorithm);
        }
    }
}
