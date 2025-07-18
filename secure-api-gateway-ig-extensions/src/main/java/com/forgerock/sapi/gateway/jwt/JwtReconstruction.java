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

import static org.forgerock.json.jose.utils.Utils.decodeJwtComponent;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.exceptions.JwtReconstructionException;
import org.forgerock.json.jose.exceptions.JwtRuntimeException;
import org.forgerock.json.jose.exceptions.UnrecognizedCriticalHeaderException;
import org.forgerock.json.jose.jwe.CompressionManager;
import org.forgerock.json.jose.jwe.EncryptedJwt;
import org.forgerock.json.jose.jwe.JweHeader;
import org.forgerock.json.jose.jwe.JweHeaderKey;
import org.forgerock.json.jose.jwe.SignedThenEncryptedJwt;
import org.forgerock.json.jose.jws.EncryptedThenSignedJwt;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.JwsHeaderKey;
import org.forgerock.json.jose.jws.JwtSecureHeader;
import org.forgerock.json.jose.jws.SignedEncryptedJwt;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.jose.jwt.JwtHeaderKey;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.util.encode.Base64url;

/**
 * A service that provides a method for reconstruct a JWT string back into its relevant JWT object,
 * ({@link SignedJwt}, {@link EncryptedJwt}, {@link SignedThenEncryptedJwt}, {@link EncryptedThenSignedJwt}).
 * This differs from the COMMONS {@link org.forgerock.json.jose.common.JwtReconstruction} class on which it is based in that it supports non-JSON
 * payloads through the use of COMMONS @link Payload}, which is already supported by e.g.the {@link SignedJwt} class.
 *
 * @since 2.0.0
 */
public class JwtReconstruction {
    private static final String PAYLOAD_CONTENT_TYPE = JwsHeaderKey.CTY.value();
    private static final String ENCRYPTION_METHOD = JweHeaderKey.ENC.value();
    private static final String ALGORITHM = JwtHeaderKey.ALG.value();
    private static final String CRITICAL_HEADERS = JwsHeaderKey.CRIT.value();

    private static final int JWS_NUM_PARTS = 3;
    private static final int JWE_NUM_PARTS = 5;

    private final Set<String> recognizedHeaders = new CopyOnWriteArraySet<>();

    /**
     * Functional interface supporting building a {@link Jwt} from its component parts. This interface supports building
     * of the {@link Jwt} with varying payload types.
     */
    @FunctionalInterface
    interface JwtBuilder {
        /**
         * Build a {@link Jwt} from its component parts.
         * @param jwtParts The {@link Jwt} component parts
         * @return a built {@link Jwt}
         */
        Jwt build(String[] jwtParts);
    }

    /**
     * Default constructor.
     */
    public JwtReconstruction() {
        // Although standard headers are not supposed to appear in the "crit" (critical header) header, we add them
        // all here so that they are ignored in case someone accidentally does it anyway.
        Set<String> standardHeaders = new HashSet<>();
        Arrays.stream(JwsHeaderKey.values()).map(JwsHeaderKey::value).forEach(standardHeaders::add);
        Arrays.stream(JweHeaderKey.values()).map(JweHeaderKey::value).forEach(standardHeaders::add);
        standardHeaders.remove("custom");
        recognizedHeaders.addAll(standardHeaders);
    }

    /**
     * Configures additional application-specific header values that are understood and processed by the application.
     * Any non-standard {@linkplain JwtSecureHeader#getCriticalHeaders() critical headers} that are not in this list
     * will cause processing to fail.
     *
     * @param headers the set of headers to add to the recognized set.
     * @return the updated JwtReconstruction object.
     */
    public JwtReconstruction recognizedHeaders(String... headers) {
        recognizedHeaders.addAll(List.of(headers));
        return this;
    }

    /**
     * Reconstructs the given JWT string into a JWT object of the specified type. The {@code jwtString} is expected to
     * be of JSON format. This method is basically a wrapper around {@link #reconstructJwtFromJsonClaims(String, Class)}
     * method, supporting the original implementation.
     *
     * @param jwtString The JWT string.
     * @param jwtClass The JWT class to reconstruct the JWT string to.
     * @param <T> The type of JWT the JWT string represents.
     * @return The reconstructed JWT object.
     * @throws InvalidJwtException If the jwt does not consist of the correct number of parts or is malformed.
     * @throws JwtReconstructionException If the jwt does not consist of the correct number of parts.
     * @throws UnrecognizedCriticalHeaderException If the JWT contains critical headers ("crit") that are
     * not {@linkplain #recognizedHeaders(String...) recognized by the application}.
     */
    public <T extends Jwt> T reconstructJwt(String jwtString, Class<T> jwtClass) {
            return reconstructJwtFromJsonClaims(jwtString, jwtClass);
    }

    /**
     * Reconstructs the given JWT string into a JWT object of the specified type. The {@code jwtString} is expected to
     * be of JSON format.
     *
     * @param jwtString The JWT string.
     * @param jwtClass The JWT class to reconstruct the JWT string to.
     * @param <T> The type of JWT the JWT string represents.
     * @return The reconstructed JWT object.
     * @throws InvalidJwtException If the jwt does not consist of the correct number of parts or is malformed.
     * @throws JwtReconstructionException If the jwt does not consist of the correct number of parts.
     * @throws UnrecognizedCriticalHeaderException If the JWT contains critical headers ("crit") that are
     * not {@linkplain #recognizedHeaders(String...) recognized by the application}.
     */
    public <T extends Jwt> T reconstructJwtFromJsonClaims(String jwtString, Class<T> jwtClass) {
        return reconstructJwt(jwtString, jwtClass, this::reconstructSignedJwtFromJsonPayload);
    }

    /**
     * Reconstructs the given JWT string into a JWT object of the specified type. The {@code jwtString} is expected to
     * be a basic String format, to accommodate receipt of String-based XML.
     *
     * @param jwtString The JWT string.
     * @param jwtClass The JWT class to reconstruct the JWT string to.
     * @param <T> The type of JWT the JWT string represents.
     * @return The reconstructed JWT object.
     * @throws InvalidJwtException If the jwt does not consist of the correct number of parts or is malformed.
     * @throws JwtReconstructionException If the jwt does not consist of the correct number of parts.
     * @throws UnrecognizedCriticalHeaderException If the JWT contains critical headers ("crit") that are
     * not {@linkplain #recognizedHeaders(String...) recognized by the application}.
     */
    public <T extends Jwt> T reconstructJwtFromString(String jwtString, Class<T> jwtClass) {
        if (jwtClass.isAssignableFrom(EncryptedJwt.class) || jwtClass.isAssignableFrom(EncryptedThenSignedJwt.class)) {
            throw new IllegalStateException("EncryptedJwt and EncryptedThenSignedJwt do not yet"
                                                    + " support string-based JWT payloads");
        }
        return reconstructJwt(jwtString, jwtClass, this::reconstructSignedJwtFromStringBasedPayload);
    }

    /**
     * Reconstructs the given JWT string into a JWT object of the specified type.
     *
     * @param jwtString The JWT string.
     * @param jwtClass The JWT class to reconstruct the JWT string to.
     * @param <T> The type of JWT the JWT string represents.
     * @return The reconstructed JWT object.
     * @throws InvalidJwtException If the jwt does not consist of the correct number of parts or is malformed.
     * @throws JwtReconstructionException If the jwt does not consist of the correct number of parts.
     * @throws UnrecognizedCriticalHeaderException If the JWT contains critical headers ("crit") that are
     * not {@linkplain #recognizedHeaders(String...) recognized by the application}.
     */
    public <T extends Jwt> T reconstructJwt(String jwtString, Class<T> jwtClass, JwtBuilder jwtBuilder) {
        //split into parts
        if (null == jwtString) {
            throw new InvalidJwtException("JWT is empty");
        }
        String[] jwtParts = jwtString.split("\\.", -1);
        if (jwtParts.length != 3 && jwtParts.length != 5) {
            throw new InvalidJwtException("not right number of dots, " + jwtParts.length);
        }

        //first part always header
        //turn into json value
        String headerDecoded = decodeJwtComponent(jwtParts[0]);
        JsonValue headerJson = new JsonValue(Utils.parseJson(headerDecoded));

        List<String> criticalHeaders =
                new ArrayList<>(headerJson.get(CRITICAL_HEADERS).defaultTo(List.of()).asList(String.class));
        criticalHeaders.removeAll(recognizedHeaders);
        if (!criticalHeaders.isEmpty()) {
            throw new UnrecognizedCriticalHeaderException(criticalHeaders);
        }

        String contentType = null;
        if (headerJson.isDefined(PAYLOAD_CONTENT_TYPE)) {
            contentType = headerJson.get(PAYLOAD_CONTENT_TYPE).asString();
        }

        final Jwt jwt;
        if (headerJson.isDefined(ENCRYPTION_METHOD)) {
            //is encrypted jwt
            verifyNumberOfParts(jwtParts, JWE_NUM_PARTS);
            jwt = reconstructEncryptedJwt(jwtParts);
        } else if ("JWT".equalsIgnoreCase(contentType) || "JWE".equalsIgnoreCase(contentType)) {
            verifyNumberOfParts(jwtParts, JWS_NUM_PARTS);
            jwt = reconstructEncryptedThenSignedJwt(jwtParts);
        } else if (headerJson.isDefined(ALGORITHM)) {
            //is signed jwt
            verifyNumberOfParts(jwtParts, JWS_NUM_PARTS);
            jwt = jwtBuilder.build(jwtParts);
        } else {
            //plaintext jwt
            verifyNumberOfParts(jwtParts, JWS_NUM_PARTS);
            if (!jwtParts[2].isEmpty()) {
                throw new InvalidJwtException("Third part of Plaintext JWT not empty.");
            }
            jwt = jwtBuilder.build(jwtParts);
        }

        return jwtClass.cast(jwt);
    }

    /**
     * Verifies that the JWT parts are the required length for the JWT type being reconstructed.
     *
     * @param jwtParts The JWT parts.
     * @param required The required number of parts.
     * @throws JwtReconstructionException If the jwt does not consist of the correct number of parts.
     */
    private void verifyNumberOfParts(String[] jwtParts, int required) {
        if (jwtParts.length != required) {
            throw new JwtReconstructionException("Not the correct number of JWT parts. Expecting, " + required
                                                         + ", actually, " + jwtParts.length);
        }
    }

    /**
     * Reconstructs a Signed JWT from the given JWT string parts.
     * <p>
     * As a plaintext JWT is a JWS with an empty signature, this method should be used to reconstruct plaintext JWTs
     * as well as signed JWTs.
     *
     * @param jwtParts The three base64url UTF-8 encoded string parts of a plaintext or signed JWT.
     * @return A SignedJwt object.
     */
    private SignedJwt reconstructSignedJwtFromJsonPayload(String[] jwtParts) {

        String encodedHeader = jwtParts[0];
        String encodedClaimsSet = jwtParts[1];
        String encodedSignature = jwtParts[2];

        String header = decodeJwtComponent(encodedHeader);


        try {
            byte[] signature = Base64url.decodeStrict(encodedSignature);
            JwsHeader jwsHeader = new JwsHeader(Utils.parseJson(header));
            byte[] payload = new CompressionManager().decompress(jwsHeader.getCompressionAlgorithm(), encodedClaimsSet);
            JwtClaimsSet claimsSet = new JwtClaimsSet(Utils.parseJson(new String(payload, Utils.CHARSET)));
            return new SignedJwt(jwsHeader, claimsSet, (encodedHeader + "." + encodedClaimsSet).getBytes(Utils.CHARSET),
                                 signature);
        } catch (IllegalArgumentException | JwtRuntimeException e) {
            throw new InvalidJwtException(e);
        }
    }

    /**
     * Reconstructs a Signed JWT from the given JWT string parts.
     * <p>
     * As a plaintext JWT is a JWS with an empty signature, this method should be used to reconstruct plaintext JWTs
     * as well as signed JWTs.
     *
     * @param jwtParts The three base64url UTF-8 encoded string parts of a plaintext or signed JWT.
     * @return A SignedJwt object.
     */
    private SignedJwt reconstructSignedJwtFromStringBasedPayload(String[] jwtParts) {

        String encodedHeader = jwtParts[0];
        String encodedClaimsSet = jwtParts[1];
        String encodedSignature = jwtParts[2];

        String header = decodeJwtComponent(encodedHeader);

        try {
            byte[] signature = Base64url.decodeStrict(encodedSignature);
            JwsHeader jwsHeader = new JwsHeader(Utils.parseJson(header));
            byte[] payload = new CompressionManager().decompress(jwsHeader.getCompressionAlgorithm(), encodedClaimsSet);
            StringPayload stringPayload = new StringPayload(new String(payload, Utils.CHARSET));
            return new SignedJwtWithStringPayload(jwsHeader,
                                                  stringPayload,
                                                  (encodedHeader + "." + encodedClaimsSet).getBytes(Utils.CHARSET),
                                                  signature);
        } catch (IllegalArgumentException | JwtRuntimeException e) {
            throw new InvalidJwtException(e);
        }
    }

    /**
     * Reconstructs an encrypted JWT from the given JWT string parts.
     *
     * @param jwtParts The five base64url UTF-8 encoded string parts of an encrypted JWT.
     * @return An EncryptedJwt object.
     */
    private EncryptedJwt reconstructEncryptedJwt(String[] jwtParts) {

        String encodedHeader = jwtParts[0];
        String encodedEncryptedKey = jwtParts[1];
        String encodedInitialisationVector = jwtParts[2];
        String encodedCiphertext = jwtParts[3];
        String encodedAuthenticationTag = jwtParts[4];


        String header = decodeJwtComponent(encodedHeader);
        byte[] encryptedContentEncryptionKey = Base64url.decode(encodedEncryptedKey);
        byte[] initialisationVector = Base64url.decode(encodedInitialisationVector);
        byte[] ciphertext = Base64url.decode(encodedCiphertext);
        byte[] authenticationTag = Base64url.decode(encodedAuthenticationTag);

        try {
            JweHeader jweHeader = new JweHeader(Utils.parseJson(header));
            if (jweHeader.getContentType() != null) {
                return new SignedThenEncryptedJwt(jweHeader, encodedHeader, encryptedContentEncryptionKey,
                                                  initialisationVector, ciphertext, authenticationTag);
            } else {
                return new EncryptedJwt(jweHeader, encodedHeader, encryptedContentEncryptionKey, initialisationVector,
                                        ciphertext, authenticationTag);
            }
        } catch (JwtRuntimeException e) {
            throw new InvalidJwtException(e);
        }
    }

    /**
     * Reconstructs a signed and encrypted JWT from the given JWT string parts.
     * <p>
     * First reconstructs the nested encrypted JWT from within the signed JWT and then reconstructs the signed JWT using
     * the reconstructed nested EncryptedJwt.
     *
     * @param jwtParts The three base64url UTF-8 encoded string parts of a signed JWT.
     * @return A SignedEncryptedJwt object.
     */
    private EncryptedThenSignedJwt reconstructEncryptedThenSignedJwt(String[] jwtParts) {

        String encodedHeader = jwtParts[0];
        String encodedPayload = jwtParts[1];
        String encodedSignature = jwtParts[2];


        String header = decodeJwtComponent(encodedHeader);
        String payloadString = decodeJwtComponent(encodedPayload);
        byte[] signature = Base64url.decode(encodedSignature);

        //split into parts
        String[] encryptedJwtParts = payloadString.split("\\.", -1);
        verifyNumberOfParts(encryptedJwtParts, JWE_NUM_PARTS);
        EncryptedJwt encryptedJwt = reconstructEncryptedJwt(encryptedJwtParts);

        Map<String, Object> combinedHeader = new HashMap<>(encryptedJwt.getHeader().getParameters());
        combinedHeader.remove(JwsHeaderKey.KID.value());
        combinedHeader.putAll(Utils.parseJson(header));

        try {
            JwsHeader jwsHeader = new JwsHeader(combinedHeader);

            // This can be changed to return EncryptedThenSignedJwt once SignedEncryptedJwt is removed
            return new SignedEncryptedJwt(jwsHeader, encryptedJwt,
                                          (encodedHeader + "." + encodedPayload).getBytes(Utils.CHARSET), signature);
        } catch (JwtRuntimeException e) {
            throw new InvalidJwtException(e);
        }
    }
}

