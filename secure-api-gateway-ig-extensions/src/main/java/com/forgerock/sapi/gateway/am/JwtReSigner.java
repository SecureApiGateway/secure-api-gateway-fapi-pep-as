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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.jose.utils.JoseSecretConstraints.allowedAlgorithm;
import static org.forgerock.openig.util.JsonValues.purposeOf;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.promise.NeverThrowsException.neverThrownAsync;

import java.security.SignatureException;

import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JwtReSigner takes a JWT as input, verifies its signature, and then re-signs the JWT with a configured signing key.
 * <p>
 * Certain use cases, such as OpenBanking UK, require keys from an external (to AM) jwks_uri be used to sign JWTs.
 * AM can be configured to use these private keys via secret mappings, but there is an issue with how AM determines
 * the kid value to use in the JWS header.
 * For the OpenBanking UK case, the kid value does not match what is expected which means that clients will not trust
 * JWT values return by AM.
 * <p>
 * To resolve this issue, this class decodes the JWTs returned by AM and creates a new one with the correct kid,
 * it is then signed using a private key that must be configured to match the expected key in the external jwks_uri
 * <p>
 * There is a ticket open with AM to fix this issue: <a href="https://bugster.forgerock.org/jira/browse/OPENAM-15617">OPENAM-15617</a>
 */
public class JwtReSigner {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * SigningManager containing AM Secrets to be used to validate that JWTs in the response path have been signed
     * correctly by AM before we re-sign them.
     */
    private final SigningManager verificationSigningManager;
    /**
     * Purpose used to find the VerificationKey in the verificationSigningManager to verify signatures with
     */
    private final Purpose<VerificationKey> verificationKeyPurpose;
    /**
     * The kid value to specify in the header of the re-signed JWT (must match a value in the trusted directories' jwks_uri)
     */
    private final String signingKeyId;
    /**
     * Purpose used to find the SigningKey in the SigningManager, should be configured to find the private key for
     * the signingKeyId
     */
    private final Purpose<SigningKey> signingKeyPurpose;
    /**
     * Created using the {@link SecretsProvider} passed to the constructor, used to create new {@link SigningHandler}
     * objects on a per Response processing basis.
     */
    private final SigningManager signingManager;
    /**
     * Transforms a compact serialized JWT string into a SignedJwt object
     */
    private final JwtReconstruction jwtReconstruction = new JwtReconstruction();

    public JwtReSigner(SecretsProvider verificationSecretsProvider, Purpose<VerificationKey> verificationKeyPurpose,
                       String signingKeyId, SecretsProvider signingSecretsProvider, Purpose<SigningKey> signingKeyPurpose) {

        Reject.ifNull(verificationSecretsProvider, "verificationSecretsProvider must be supplied");
        Reject.ifNull(verificationKeyPurpose, "verificationKeyPurpose must be supplied");
        Reject.ifNull(signingKeyId, "signingKeyId must be supplied");
        Reject.ifNull(signingSecretsProvider, "signingSecretsProvider must be supplied");
        Reject.ifNull(signingKeyPurpose, "signingKeyPurpose must be supplied");
        this.verificationSigningManager = new SigningManager(verificationSecretsProvider);
        this.verificationKeyPurpose = verificationKeyPurpose;
        this.signingKeyId = signingKeyId;
        this.signingKeyPurpose = signingKeyPurpose;
        this.signingManager = new SigningManager(signingSecretsProvider);
    }

    /**
     * Re-signs a jwtString using the configured signingKeyId and signingHandler.
     *
     * @param jwtString the JWT to re-sign in compact serialization format
     * @return Promise<String, SignatureException> with either the re-signed JWT in compact serialization format
     * or a SignatureException if an error occurred in either validating the jwtString param's signature or computing
     * the new signature.
     */
    public Promise<String, SignatureException> reSignJwt(String jwtString) {
        final SignedJwt signedJwt;
        try {
            signedJwt = jwtReconstruction.reconstructJwt(jwtString, SignedJwt.class);
        } catch (InvalidJwtException ex) {
            logger.debug("Cannot re-sign jwt: {} as it is not a valid jwt", jwtString);
            return Promises.newExceptionPromise(new SignatureException("Invalid jwtString supplied", ex));
        }
        return reSignJwt(signedJwt).then(SignedJwt::build);
    }

    /**
     * Re-signs a {@link SignedJwt} using the configured signingKeyId and signingHandler.
     *
     * @param signedJwt the {@link SignedJwt} to re-sign
     * @return Promise<SignedJwt, SignatureException> with either return the re-signed JWT or a SignatureException if
     * an error occurred in either validating the signedJwt param's signature or computing the new signature.
     */
    public Promise<SignedJwt, SignatureException> reSignJwt(SignedJwt signedJwt) {
        return verifyAmSignedIdToken(signedJwt).thenAsync(signatureValid -> {
            if (!signatureValid) {
                logger.error("Cannot re-sign jwt: {} as it does not have a valid signature", signedJwt);
                return Promises.newExceptionPromise(new SignatureException("Unable to re-sign JWT - signature not valid for configured AM signing key"));
            }
            return signingManager.newSigningHandler(signingKeyPurpose).then(signingHandler -> reSignJwt(signedJwt, signingHandler),
                                                                            nsse -> {
                                                                                throw new SignatureException("Failed to create signingHandler", nsse);
                                                                            });
        }, neverThrownAsync());
    }

    /**
     * Re-signs the supplied jwt using the signingKeyId and supplied signingHandler
     *
     * @param signedJwt      SignedJwt the JWT to re-sign
     * @param signingHandler SigningHandler capable of signing the JWT
     * @return String jwt signed using the signingKeyId
     */
    private SignedJwt reSignJwt(SignedJwt signedJwt, SigningHandler signingHandler) {
        final JwsHeader headerWithCorrectKeyId = new JwsHeader(signedJwt.getHeader().getParameters());
        headerWithCorrectKeyId.setKeyId(signingKeyId);
        return new SignedJwt(headerWithCorrectKeyId, signedJwt.getClaimsSet(), signingHandler);
    }

    /**
     * Method to verify that the SignedJwt was signed by AM
     *
     * @param signedJwt SignedJwt the JWT to verify that AM has signed
     * @return Promise<Boolean, NeverThrowsException> the result of signature verification
     */
    private Promise<Boolean, NeverThrowsException> verifyAmSignedIdToken(SignedJwt signedJwt) {
        final JwsAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();
        final Purpose<VerificationKey> constrainedPurpose =
                verificationKeyPurpose.withConstraints(allowedAlgorithm(algorithm));

        final String keyId = signedJwt.getHeader().getKeyId();
        return verificationSigningManager.newVerificationHandler(constrainedPurpose, keyId)
                                         .then(signedJwt::verify);
    }

    /**
     * Heaplet which creates {@link JwtReSigner} objects.
     * <p>
     * Configuration:
     * <ul>
     * <li>verificationSecretsProvider the name of the SecretsProvider heap object that contains the AM secrets
*                                      used to verify the JWT param was signed by AM before re-signing it.</li>
     * <li>verificationSecretId the secret id of the verification key in the verificationSecretsProvider.
     *                        Note: when using a {@link org.forgerock.secrets.jwkset.JwkSetSecretStore} based provider
     *                        then this value is not used in the key lookup but must be a non-blank value</li>
     * <li>signingKeyId the kid value to specify in the re-signed JWS header</li>
     * <li>signingSecretsProvider the name of the SecretsProvider heap object that contains the signing private key for the kid</li>
     * <li>signingKeySecretId the secretId used to find the signing key in the secretsProvider</li>
     * </ul>
     * <p>
     * Example config:
     * <pre>{@code
     * {
     *   "name": "JwtReSigner",
     *   "type": "JwtReSigner",
     *   "comment": "Re-sign an JWT returned by AM to fix the keyId issue",
     *   "config": {
     *     "verificationSecretsProvider": "SecretsProvider-AmJWK",
     *     "verificationSecretId": "any.valid.regex.value",
     *     "signingKeyId": "&{ig.ob.aspsp.signing.kid}",
     *     "signingSecretsProvider": "SecretsProvider-ASPSP",
     *     "signingKeySecretId": "jwt.signer",
     *   }
     *}
     *}</pre>
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final SecretsProvider signingSecretsProvider = config.get("signingSecretsProvider")
                                                                 .as(requiredHeapObject(heap, SecretsProvider.class));
            final Purpose<SigningKey> signingKeyPurpose = config.get("signingKeySecretId")
                                                                .as(purposeOf(SigningKey.class));

            final SecretsProvider verificationSecretsProvider = config.get("verificationSecretsProvider")
                                                                      .as(requiredHeapObject(heap, SecretsProvider.class));
            final Purpose<VerificationKey> verificationKeyPurpose = config.get("verificationSecretId")
                                                                          .as(purposeOf(VerificationKey.class));

            final String signingKeyId = config.get("signingKeyId").asString();
            return new JwtReSigner(verificationSecretsProvider, verificationKeyPurpose, signingKeyId,
                                   signingSecretsProvider, signingKeyPurpose);
        }
    }

}
