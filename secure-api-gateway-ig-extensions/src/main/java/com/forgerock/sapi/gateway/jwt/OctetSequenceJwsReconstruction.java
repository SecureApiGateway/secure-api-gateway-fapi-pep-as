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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.exceptions.JwtReconstructionException;
import org.forgerock.json.jose.exceptions.JwtRuntimeException;
import org.forgerock.json.jose.exceptions.UnrecognizedCriticalHeaderException;
import org.forgerock.json.jose.jwe.CompressionManager;
import org.forgerock.json.jose.jwe.JweHeaderKey;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.JwsHeaderKey;
import org.forgerock.json.jose.jws.JwtSecureHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.json.jose.jwt.JwtHeaderKey;
import org.forgerock.json.jose.jwt.Payload;
import org.forgerock.json.jose.utils.Utils;
import org.forgerock.util.encode.Base64url;

/**
 * A service that provides a method for reconstruct a JWS string containing an octet-sequence payload back into its
 * respective {@link OctetSequenceSignedJwt}.
 * <p>
 * This expands on the COMMONS {@link org.forgerock.json.jose.common.JwtReconstruction} class on which it is based in
 * that it supports non-JSON payloads through the use of COMMONS {@link Payload}, which is already supported by e.g. the
 * {@link SignedJwt} class. Note that this implementation does not support building these other JWT types.
 * <p>
 * N.B. This class is introduced for OpenBanking OPENIG-9436, but is expected to be temporary until COMMONS can be
 * retrofitted to support octet-sequence JWS and JWE payloads (COMMONS-1558). There are a number of constraints that
 * make that not immediately straightforward.
 */
public class OctetSequenceJwsReconstruction {
    private static final String PAYLOAD_CONTENT_TYPE = JwsHeaderKey.CTY.value();
    private static final String ENCRYPTION_METHOD = JweHeaderKey.ENC.value();
    private static final String ALGORITHM = JwtHeaderKey.ALG.value();
    private static final String CRITICAL_HEADERS = JwsHeaderKey.CRIT.value();

    private static final int JWS_NUM_PARTS = 3;

    private final Set<String> recognizedHeaders = new CopyOnWriteArraySet<>();

    /**
     * Default constructor.
     */
    public OctetSequenceJwsReconstruction() {
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
    public OctetSequenceJwsReconstruction recognizedHeaders(String... headers) {
        recognizedHeaders.addAll(List.of(headers));
        return this;
    }

    /**
     * Reconstructs the given encoded octet-sequence JWS string into a JWS object of the specified type. The
     * {@code jwtString} is expected to contain an octet-sequence UTF-8 payload.
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
        if (!SignedJwt.class.isAssignableFrom(jwtClass)) {
            throw new IllegalStateException("Only plain SignedJwt currently supports octet sequence JWT payloads");
        }
        //split into parts
        if (null == jwtString) {
            throw new InvalidJwtException("JWT is empty");
        }
        String[] jwtParts = jwtString.split("\\.", -1);
        if (jwtParts.length != 3) {
            throw new InvalidJwtException("not right number of dots for a JWS, " + jwtParts.length);
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
        // Only signed JWT format is acceptable
        if (headerJson.isDefined(ENCRYPTION_METHOD)) {
            //is encrypted jwt
            throw new InvalidJwtException("Octet-sequence payload only supported with JWS");
        } else if ("JWT".equalsIgnoreCase(contentType) || "JWE".equalsIgnoreCase(contentType)) {
            throw new InvalidJwtException("Octet-sequence payload is not expected to contain nested JWT or JWE");
        } else if (headerJson.isDefined(ALGORITHM)) {
            //is signed jwt
            verifyNumberOfParts(jwtParts, JWS_NUM_PARTS);
            jwt = reconstructOctetSequenceJws(jwtParts);
        } else {
            //plaintext jwt
            verifyNumberOfParts(jwtParts, JWS_NUM_PARTS);
            if (!jwtParts[2].isEmpty()) {
                throw new InvalidJwtException("Third part of Plaintext JWT not empty.");
            }
            jwt = reconstructOctetSequenceJws(jwtParts);
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
    private SignedJwt reconstructOctetSequenceJws(String[] jwtParts) {

        String encodedHeader = jwtParts[0];
        String encodedClaimsSet = jwtParts[1];
        String encodedSignature = jwtParts[2];
        String header = decodeJwtComponent(encodedHeader);
        try {
            byte[] signature = Base64url.decodeStrict(encodedSignature);
            JwsHeader jwsHeader = new JwsHeader(Utils.parseJson(header));
            byte[] payloadBytes = new CompressionManager().decompress(jwsHeader.getCompressionAlgorithm(), encodedClaimsSet);
            byte[] signingInput = (encodedHeader + "." + encodedClaimsSet).getBytes(Utils.CHARSET);
            OctetSequencePayload octetSequencePayload = new OctetSequencePayload(payloadBytes);
            return new OctetSequenceSignedJwt(jwsHeader, octetSequencePayload, signingInput, signature);
        } catch (IllegalArgumentException | JwtRuntimeException e) {
            throw new InvalidJwtException(e);
        }
    }
}

