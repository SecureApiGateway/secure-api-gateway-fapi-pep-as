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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;

import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.trusteddirectories.DefaultTrustedDirectory.Builder;

class DefaultTrustedDirectoryTest {

    static final URI DIRECTORY_JWKS_URI = URI.create("https://test-directory/jwks");
    static final String ISSUER = "Test Directory";
    static final String SOFTWARE_JWKS_URI_CLAIM_NAME = "software_jwks_endpoint";
    static final String SOFTWARE_JWKS_CLAIM_NAME = "embedded_jwks";
    static final String SOFTWARE_ORG_ID_CLAIM_NAME = "software_org_id";
    static final String SOFTWARE_ORG_NAME_CLAIM_NAME = "software_org_name";
    static final String SOFTWARE_ID_CLAIM_NAME = "software_id";
    static final String SOFTWARE_REDIRECT_URIS_CLAIM_NAME = "software_redirect_uri";
    static final String SOFTWARE_ROLES_CLAIM_NAME = "software_roles";
    static final String SOFTWARE_CLIENT_NAME_CLAIM_NAME = "software_client_name";

    @Test
    void createsTrustedDirectoryWithJwksUri() {
        validateTrustedDirectoryWithJwksUri(createTrustedDirectoryWithJwksUri());
    }

    private static DefaultTrustedDirectory createTrustedDirectoryWithJwksUri() {
        return createBuilderWithJwksUri().build();
    }

    private static Builder createBuilderWithJwksUri() {
        return createBuilderWithMandatoryFieldsOnly().setSoftwareStatementJwksUriClaimName(SOFTWARE_JWKS_URI_CLAIM_NAME);
    }

    @Test
    void createsTrustedDirectoryWithEmbeddedJwks() {
        final DefaultTrustedDirectory trustedDirectory = createTrustedDirectoryWithEmbeddedJwks();

        validateTrustedDirectoryWithEmbeddedJwks(trustedDirectory);
    }

    private static DefaultTrustedDirectory createTrustedDirectoryWithEmbeddedJwks() {
        return createBuilderWithMandatoryFieldsOnly().setSoftwareStatementJwksClaimName(SOFTWARE_JWKS_CLAIM_NAME)
                                                     .build();
    }

    @Test
    void createsTrustedDirectoryThatIsDisabled() {
        final DefaultTrustedDirectory trustedDirectory = createBuilderWithJwksUri().setDisabled(true).build();
        assertThat(trustedDirectory.isDisabled()).isTrue();
    }

    @Test
    void failsWhenBothJwksUriClaimNameAndJwksClaimNameAreSet() {
        final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
                () -> createBuilderWithMandatoryFieldsOnly()
                    .setSoftwareStatementJwksUriClaimName(SOFTWARE_JWKS_URI_CLAIM_NAME)
                    .setSoftwareStatementJwksClaimName(SOFTWARE_JWKS_CLAIM_NAME)
                    .build());
        assertThat(illegalArgumentException.getMessage()).isEqualTo(
                "Exactly one of softwareStatementJwksUriClaimName or softwareStatementJwksClaimName must be supplied");
    }

    @Test
    void failsWhenBothJwksUriClaimNameAndJwksClaimNameAreNull() {
        final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
                () -> createBuilderWithMandatoryFieldsOnly().build());
        assertThat(illegalArgumentException.getMessage()).isEqualTo(
                "Exactly one of softwareStatementJwksUriClaimName or softwareStatementJwksClaimName must be supplied");
    }

    @Test
    void failsToBuildWhenDirectoryJwksUriIsMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setDirectoryJwksUri(null).build());

        assertThat(npe.getMessage()).isEqualTo("directoryJwksUri must be supplied");
    }


    @Test
    void failsToBuildWhenIssuerIsMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setIssuer(null).build());

        assertThat(npe.getMessage()).isEqualTo("issuer must be supplied");
    }

    @Test
    void failsToBuildWhenSoftwareOrgIdIsMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setSoftwareStatementOrgIdClaimName(null).build());

        assertThat(npe.getMessage()).isEqualTo("softwareStatementOrgIdClaimName must be supplied");
    }

    @Test
    void failsToBuildWhenSoftwareOrgNameIsMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setSoftwareStatementOrgNameClaimName(null).build());

        assertThat(npe.getMessage()).isEqualTo("softwareStatementOrgNameClaimName must be supplied");
    }

    @Test
    void failsToBuildWhenSoftwareIdMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setSoftwareStatementSoftwareIdClaimName(null).build());

        assertThat(npe.getMessage()).isEqualTo("softwareStatementSoftwareIdClaimName must be supplied");
    }

    @Test
    void failsToBuildWhenRedirectUrisMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setSoftwareStatementRedirectUrisClaimName(null).build());

        assertThat(npe.getMessage()).isEqualTo("softwareStatementRedirectUrisClaimName must be supplied");
    }

    @Test
    void failsToBuildWhenRolesMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setSoftwareStatementRolesClaimName(null).build());

        assertThat(npe.getMessage()).isEqualTo("softwareStatementRolesClaimName must be supplied");
    }

    @Test
    void failsToBuildWhenSoftwareClientNameMissing() {
        final NullPointerException npe = assertThrows(NullPointerException.class,
                () -> createBuilderWithJwksUri().setSoftwareStatementClientNameClaimName(null).build());

        assertThat(npe.getMessage()).isEqualTo("softwareStatementClientNameClaimName must be supplied");
    }

    private static Builder createBuilderWithMandatoryFieldsOnly() {
        return DefaultTrustedDirectory.builder()
                .setDirectoryJwksUri(DIRECTORY_JWKS_URI)
                .setIssuer(ISSUER)
                .setSoftwareStatementOrgIdClaimName(SOFTWARE_ORG_ID_CLAIM_NAME)
                .setSoftwareStatementOrgNameClaimName(SOFTWARE_ORG_NAME_CLAIM_NAME)
                .setSoftwareStatementSoftwareIdClaimName(SOFTWARE_ID_CLAIM_NAME)
                .setSoftwareStatementRedirectUrisClaimName(SOFTWARE_REDIRECT_URIS_CLAIM_NAME)
                .setSoftwareStatementRolesClaimName(SOFTWARE_ROLES_CLAIM_NAME)
                .setSoftwareStatementClientNameClaimName(SOFTWARE_CLIENT_NAME_CLAIM_NAME);

    }

    static void validateTrustedDirectoryWithJwksUri(TrustedDirectory trustedDirectory) {
        validateTrustedDirectoryMandatoryFields(trustedDirectory);

        assertThat(trustedDirectory.softwareStatementHoldsJwksUri()).isTrue();
        assertThat(trustedDirectory.getSoftwareStatementJwksUriClaimName()).isEqualTo(SOFTWARE_JWKS_URI_CLAIM_NAME);
        assertThat(trustedDirectory.getSoftwareStatementJwksClaimName()).isNull();
    }

    static void validateTrustedDirectoryWithEmbeddedJwks(TrustedDirectory trustedDirectory) {
        validateTrustedDirectoryMandatoryFields(trustedDirectory);

        assertThat(trustedDirectory.softwareStatementHoldsJwksUri()).isFalse();
        assertThat(trustedDirectory.getSoftwareStatementJwksUriClaimName()).isNull();
        assertThat(trustedDirectory.getSoftwareStatementJwksClaimName()).isEqualTo(SOFTWARE_JWKS_CLAIM_NAME);
    }

    static void validateTrustedDirectoryMandatoryFields(TrustedDirectory trustedDirectory) {
        assertThat(trustedDirectory.getDirectoryJwksUri()).isEqualTo(DIRECTORY_JWKS_URI);
        assertThat(trustedDirectory.getIssuer()).isEqualTo(ISSUER);
        assertThat(trustedDirectory.getSoftwareStatementOrgIdClaimName()).isEqualTo(SOFTWARE_ORG_ID_CLAIM_NAME);
        assertThat(trustedDirectory.getSoftwareStatementOrgNameClaimName()).isEqualTo(SOFTWARE_ORG_NAME_CLAIM_NAME);
        assertThat(trustedDirectory.getSoftwareStatementSoftwareIdClaimName()).isEqualTo(SOFTWARE_ID_CLAIM_NAME);
        assertThat(trustedDirectory.getSoftwareStatementRedirectUrisClaimName()).isEqualTo(SOFTWARE_REDIRECT_URIS_CLAIM_NAME);
        assertThat(trustedDirectory.getSoftwareStatementRolesClaimName()).isEqualTo(SOFTWARE_ROLES_CLAIM_NAME);
        assertThat(trustedDirectory.getSoftwareStatementClientNameClaimName()).isEqualTo(SOFTWARE_CLIENT_NAME_CLAIM_NAME);
    }

}