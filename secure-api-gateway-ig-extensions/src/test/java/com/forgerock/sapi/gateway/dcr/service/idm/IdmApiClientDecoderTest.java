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
package com.forgerock.sapi.gateway.dcr.service.idm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;

public class IdmApiClientDecoderTest {

    private final IdmApiClientDecoder idmApiClientDecoder = new IdmApiClientDecoder();

    public static JsonValue createIdmApiClientWithJwksUri(String clientId) {
        return createIdmApiClientWithJwksUri(clientId, "https://somelocation/jwks.jwks");
    }

    public static JsonValue createIdmApiClientWithJwksUri(String clientId, String jwksUri) {
        return createIdmApiClientDataInner(clientId).put("jwksUri", jwksUri);
    }

    public static JsonValue createIdmApiClientWithJwks(String clientId) {
        return createIdmApiClientDataInner(clientId).put("jwks", DCRTestHelpers.getJwksJsonValue());
    }

    private static JsonValue createIdmApiClientDataInner(String clientId) {
        return json(object(field("_id", clientId),
                           field("id", "ebSqTNqmQXFYz6VtWGXZAa"),
                           field("name", "Automated Testing"),
                           field("ssa", createTestSoftwareStatementAssertion().build()),
                           field("oauth2ClientId", clientId),
                           field("roles", array("AISP", "PISP", "CBPII")),
                           field("deleted", false),
                           field("apiClientOrg", object(field("id", "98761234"),
                           field("name", "Test Organisation")))));
    }

    /**
     * @return SignedJwt which represents a Software Statement Assertion (ssa). This is a dummy JWT in place of a real
     * software statement, it does not contain a realistic set of claims and the signature (and kid) are junk.
     *
     * This is good enough for this test as the ssa is not processed, only decoded into a SignedJwt object
     */
    private static SignedJwt createTestSoftwareStatementAssertion() {
        final JwsHeader header = new JwsHeader();
        header.setKeyId("12345");
        header.setAlgorithm(JwsAlgorithm.PS256);
        return new SignedJwt(header, new JwtClaimsSet(Map.of("claim1", "value1")), new SigningHandler() {
            @Override
            public byte[] sign(JwsAlgorithm algorithm, byte[] data) {
                return "gYdMUpAvrotMnMP8tHj".getBytes(StandardCharsets.UTF_8);
            }

            @Override
            public boolean verify(JwsAlgorithm algorithm, byte[] data, byte[] signature) {
                return false;
            }
        });
    }

    public static void verifyIdmClientDataMatchesApiClientObject(JsonValue idmClientData, ApiClient actualApiClient) {
        verifyIdmClientDataMatchesApiClientObject(idmClientData, actualApiClient, false);
    }

    public static void verifyIdmClientDataMatchesApiClientObject(JsonValue idmClientData, ApiClient actualApiClient, boolean deleted) {
        assertEquals(idmClientData.get("id").asString(), actualApiClient.getSoftwareClientId());
        assertEquals(idmClientData.get("name").asString(), actualApiClient.getClientName());
        assertEquals(idmClientData.get("oauth2ClientId").asString(), actualApiClient.getOAuth2ClientId());
        final JsonValue jwksUri = idmClientData.get("jwksUri");
        if (jwksUri.isNotNull()) {
            assertEquals(jwksUri.asString(), actualApiClient.getJwksUri().toString());
        }

        final JsonValue jwks = idmClientData.get("jwks");
        if (jwks.isNotNull()) {
            assertEquals(JWKSet.parse(jwks), actualApiClient.getJwks());
        }

        assertEquals(idmClientData.get("apiClientOrg").get("id").asString(), actualApiClient.getOrganisation().id());
        assertEquals(idmClientData.get("apiClientOrg").get("name").asString(), actualApiClient.getOrganisation().name());
        assertEquals(idmClientData.get("roles").asList(String.class), actualApiClient.getRoles());

        final String ssaStr = idmClientData.get("ssa").asString();
        final SignedJwt expectedSignedJwt = new JwtReconstruction().reconstructJwt(ssaStr, SignedJwt.class);
        assertEquals(expectedSignedJwt.getHeader(), actualApiClient.getSoftwareStatementAssertion().getHeader());
        assertEquals(expectedSignedJwt.getClaimsSet(), actualApiClient.getSoftwareStatementAssertion().getClaimsSet());

        assertThat(actualApiClient.isDeleted()).isEqualTo(deleted);
    }

    @Test
    void decodeApiClientAllFieldsSet() {
        final JsonValue idmJson = createIdmApiClientWithJwksUri("1234");
        final ApiClient apiClient = new IdmApiClientDecoder().decode(idmJson);
        verifyIdmClientDataMatchesApiClientObject(idmJson, apiClient);
    }

    @Test
    void decodeApiClientRequiredFieldsOnly() {
        final JsonValue idmJson = createIdmApiClientWithJwks("9999");
        final ApiClient apiClient = idmApiClientDecoder.decode(idmJson);
        verifyIdmClientDataMatchesApiClientObject(idmJson, apiClient);
        assertNull(apiClient.getJwksUri(), "jwksUri must be null");
    }

    @Test
    void failToDecodeMissingMandatoryFields() {
        JsonValueException decodeException = assertThrows(JsonValueException.class,
                () -> idmApiClientDecoder.decode(json(object())));
        assertEquals("/name: is a required field, failed to decode IDM ApiClient", decodeException.getMessage());

        // Test with ssa field missing
        final JsonValue missingSsaField = createIdmApiClientWithJwks("123454");
        missingSsaField.remove("ssa");
        decodeException = assertThrows(JsonValueException.class, () -> idmApiClientDecoder.decode(missingSsaField));
        assertEquals("/ssa: is a required field, failed to decode IDM ApiClient", decodeException.getMessage());

        // Test with apiClientOrg.id field missing
        final JsonValue missingOrgId = createIdmApiClientWithJwks("2323");
        missingOrgId.get("apiClientOrg").remove("id");
        decodeException = assertThrows(JsonValueException.class, () -> idmApiClientDecoder.decode(missingOrgId));
        assertEquals("/apiClientOrg/id: is a required field, failed to decode IDM ApiClient", decodeException.getMessage());
    }

    @Test
    void failToDecodeDueToRolesFieldInvalidType() {
        final JsonValue invalidRoles = createIdmApiClientWithJwks("2323");
        invalidRoles.put("roles", "ROLE1,ROLE2");
        JsonValueException decodeException = assertThrows(JsonValueException.class, () -> idmApiClientDecoder.decode(invalidRoles));
        assertEquals("/roles: Expecting a List of java.lang.String elements", decodeException.getMessage());

        invalidRoles.put("roles", array(1,2,3));
        decodeException = assertThrows(JsonValueException.class, () -> idmApiClientDecoder.decode(invalidRoles));
        assertEquals("/roles: Expecting a List of java.lang.String elements", decodeException.getMessage());
    }

    @Test
    void failToDecodeDueToUnexpectedException() {
        final JsonValue corruptSsaField = createIdmApiClientWithJwks("123454");
        corruptSsaField.put("ssa", "This is not a JWT");

        JsonValueException decodeException = assertThrows(JsonValueException.class, () -> idmApiClientDecoder.decode(corruptSsaField));
        assertEquals("/ssa: failed to decode JWT, raw jwt string: This is not a JWT", decodeException.getMessage());
        assertThat(decodeException.getCause()).isInstanceOf(InvalidJwtException.class);
    }
}