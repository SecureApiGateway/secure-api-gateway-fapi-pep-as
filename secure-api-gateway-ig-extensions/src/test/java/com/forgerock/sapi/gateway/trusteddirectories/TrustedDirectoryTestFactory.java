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

import static java.util.stream.Collectors.toMap;

import java.net.URI;
import java.util.List;
import java.util.function.Function;

public class TrustedDirectoryTestFactory {

    private static final URI DIRECTORY_JWKS_URI = URI.create("https://jwks_uri.com");

    public static final String EMBEDDED_JWKS_BASED_DIRECTORY_ISSUER = "EmbeddedJwksBasedTrustedDirectory";
    public static final String JWKS_URI_BASED_DIRECTORY_ISSUER = "JwksUriBasedTrustedDirectory";

    private static final TrustedDirectory jwksUriBasedTrustedDirectory = new TrustedDirectory() {
        @Override
        public String getIssuer() {
            return JWKS_URI_BASED_DIRECTORY_ISSUER;
        }

        @Override
        public URI getDirectoryJwksUri() {
            return DIRECTORY_JWKS_URI;
        }

        @Override
        public boolean softwareStatementHoldsJwksUri() {
            return true;
        }

        @Override
        public String getSoftwareStatementJwksUriClaimName() {
            return "software_jwks_endpoint";
        }

        @Override
        public String getSoftwareStatementJwksClaimName() {
            return null;
        }

        @Override
        public String getSoftwareStatementOrgIdClaimName() {
            return "org_id";
        }

        @Override
        public String getSoftwareStatementOrgNameClaimName() {
            return "org_name";
        }

        @Override
        public String getSoftwareStatementSoftwareIdClaimName() {
            return "software_id";
        }

        @Override
        public String getSoftwareStatementRedirectUrisClaimName() {
            return "software_redirect_uris";
        }

        @Override
        public String getSoftwareStatementRolesClaimName() {
            return "software_roles";
        }

        @Override
        public String getSoftwareStatementClientNameClaimName() {
            return "software_client_name";
        }

        @Override
        public boolean isDisabled() {
            return false;
        }
    };

    private static final TrustedDirectory jwksBasedTrustedDirectory = new TrustedDirectory() {
        @Override
        public String getIssuer() {
            return EMBEDDED_JWKS_BASED_DIRECTORY_ISSUER;
        }

        @Override
        public URI getDirectoryJwksUri() {
            return DIRECTORY_JWKS_URI;
        }

        @Override
        public boolean softwareStatementHoldsJwksUri() {
            return false;
        }

        @Override
        public String getSoftwareStatementJwksUriClaimName() {
            return null;
        }

        @Override
        public String getSoftwareStatementJwksClaimName() {
            return "software_jwks";
        }

        @Override
        public String getSoftwareStatementOrgIdClaimName() {
            return "org_id";
        }

        @Override
        public String getSoftwareStatementOrgNameClaimName() {
            return "org_name";
        }

        @Override
        public String getSoftwareStatementSoftwareIdClaimName() {
            return "software_id";
        }

        @Override
        public String getSoftwareStatementRedirectUrisClaimName() {
            return "software_redirect_uris";
        }

        @Override
        public String getSoftwareStatementRolesClaimName() {
            return "software_roles";
        }

        @Override
        public String getSoftwareStatementClientNameClaimName() {
            return "software_client_name";
        }

        @Override
        public boolean isDisabled() {
            return false;
        }
    };

    public static TrustedDirectory getJwksUriBasedTrustedDirectory() {
        return jwksUriBasedTrustedDirectory;
    }

    public static TrustedDirectory getEmbeddedJwksBasedDirectoryIssuer() {
        return jwksBasedTrustedDirectory;
    }

    public static TrustedDirectoryService getTrustedDirectoryService() {
        final List<TrustedDirectory> directories = List.of(getJwksUriBasedTrustedDirectory(), getEmbeddedJwksBasedDirectoryIssuer());
        return new StaticTrustedDirectoryService(directories.stream()
                                                            .collect(toMap(TrustedDirectory::getIssuer, Function.identity())));
    }
}