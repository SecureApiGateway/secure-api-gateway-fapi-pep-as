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
package com.forgerock.sapi.gateway.trusteddirectories;

import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.DIRECTORY_JWKS_URI;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.ISSUER;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_CLIENT_NAME_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_ID_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_JWKS_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_JWKS_URI_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_ORG_ID_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_ORG_NAME_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_REDIRECT_URIS_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.SOFTWARE_ROLES_CLAIM_NAME;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.validateTrustedDirectoryWithJwksUri;
import static com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectoryTest.validateTrustedDirectoryWithEmbeddedJwks;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.junit.jupiter.api.Test;

class TrustedDirectoryHeapletTest {

    @Test
    void createTrustedDirectoryWithJwksUri() throws Exception {
        validateTrustedDirectoryWithJwksUri(invokeHeaplet(createConfigForTrustedDirectoryWithJwksUri()));
    }

    @Test
    void createTrustedDirectoryWithEmbeddedJwks() throws Exception {
        validateTrustedDirectoryWithEmbeddedJwks(invokeHeaplet(createConfigForTrustedDirectoryWithEmbeddedJwks()));
    }

    @Test
    void failsToCreateDirectoryWhenConfigIsMissingMandatoryField() {
        final JsonValue configWithMandatoryValuesOnly = createConfigWithMandatoryValuesOnly();

        for (final String fieldToOmit : configWithMandatoryValuesOnly.keys()) {
            final JsonValue config = createConfigForTrustedDirectoryWithJwksUri();
            config.remove(fieldToOmit);
            final JsonValueException ex = assertThrows(JsonValueException.class, () -> invokeHeaplet(config));
            assertThat(ex.getMessage()).contains(fieldToOmit + ": Expecting a value");
        }
    }

    @Test
    void failsToCreateDirectoryWhenJwksUriAndEmbeddedJwksConfigSupplied() {
        final JsonValue config = createConfigWithMandatoryValuesOnly()
                .put("softwareStatementJwksUriClaimName", SOFTWARE_JWKS_URI_CLAIM_NAME)
                .put("softwareStatementJwksClaimName", SOFTWARE_JWKS_CLAIM_NAME);

        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> invokeHeaplet(config));
        assertThat(ex.getMessage()).isEqualTo(
                "Exactly one of softwareStatementJwksUriClaimName or softwareStatementJwksClaimName must be supplied");
    }

    @Test
    void failsToCreateDirectoryWhenNeitherJwksUriOrEmbeddedJwksConfigSupplied() {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> invokeHeaplet(createConfigWithMandatoryValuesOnly()));
        assertThat(ex.getMessage()).isEqualTo(
                "Exactly one of softwareStatementJwksUriClaimName or softwareStatementJwksClaimName must be supplied");
    }

    private static TrustedDirectory invokeHeaplet(JsonValue config) throws HeapException {
        final TrustedDirectoryHeaplet trustedDirectoryHeaplet = new TrustedDirectoryHeaplet();
        return (TrustedDirectory) trustedDirectoryHeaplet.create(
                Name.of("test"), config, new HeapImpl(Name.of("emptyHeap")));
    }

    public static JsonValue createConfigForTrustedDirectoryWithJwksUri() {
        return createConfigWithMandatoryValuesOnly()
                .put("softwareStatementJwksUriClaimName", SOFTWARE_JWKS_URI_CLAIM_NAME);
    }

    private JsonValue createConfigForTrustedDirectoryWithEmbeddedJwks() {
        return createConfigWithMandatoryValuesOnly().put("softwareStatementJwksClaimName", SOFTWARE_JWKS_CLAIM_NAME);
    }

    private static JsonValue createConfigWithMandatoryValuesOnly() {
        return json(object(field("directoryJwksUri", DIRECTORY_JWKS_URI.toString()),
                           field("issuer", ISSUER),
                           field("softwareStatementOrgIdClaimName", SOFTWARE_ORG_ID_CLAIM_NAME),
                           field("softwareStatementOrgNameClaimName", SOFTWARE_ORG_NAME_CLAIM_NAME),
                           field("softwareStatementSoftwareIdClaimName", SOFTWARE_ID_CLAIM_NAME),
                           field("softwareStatementRedirectUrisClaimName", SOFTWARE_REDIRECT_URIS_CLAIM_NAME),
                           field("softwareStatementRolesClaimName", SOFTWARE_ROLES_CLAIM_NAME),
                           field("softwareStatementClientNameClaimName", SOFTWARE_CLIENT_NAME_CLAIM_NAME)
        ));
    }

}