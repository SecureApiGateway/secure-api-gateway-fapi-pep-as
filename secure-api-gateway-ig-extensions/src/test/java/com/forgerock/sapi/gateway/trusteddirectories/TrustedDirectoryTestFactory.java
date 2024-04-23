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

import java.net.URI;

public class TrustedDirectoryTestFactory {

    private static URI jwks_uri = URI.create("https://jwks_uri.com");

    public static String JWKS_BASED_DIRECTORY_ISSUER = "JwksBasedTrustedDirectory";
    public static String JWKS_URI_BASED_DIRECTORY_ISSUER = "JwksUriBasedTrustedDirectory";

    private static TrustedDirectory jwksUriBasedTrustedDirectory = new TrustedDirectory() {
        @Override
        public String getIssuer() {
            return JWKS_URI_BASED_DIRECTORY_ISSUER;
        }

        @Override
        public URI getDirectoryJwksUri() {
            return jwks_uri;
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
    };

    private static TrustedDirectory jwksBasedTrustedDirectory = new TrustedDirectory() {
        @Override
        public String getIssuer() {
            return JWKS_BASED_DIRECTORY_ISSUER;
        }

        @Override
        public URI getDirectoryJwksUri() {
            return jwks_uri;
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
    };

    public static TrustedDirectory getJwksUriBasedTrustedDirectory() {
        return jwksUriBasedTrustedDirectory;
    }

    public static TrustedDirectory getJwksBasedTrustedDirectory() {
        return jwksBasedTrustedDirectory;
    }

    public static TrustedDirectoryService getTrustedDirectoryService() {
        return new TrustedDirectoryService() {
            @Override
            public TrustedDirectory getTrustedDirectoryConfiguration(String issuer) {
                if (issuer.equals(jwksBasedTrustedDirectory.getIssuer())) {
                    return getJwksBasedTrustedDirectory();
                } else if (issuer.equals(jwksUriBasedTrustedDirectory.getIssuer())) {
                    return getJwksUriBasedTrustedDirectory();
                } else {
                    return null;
                }
            }
        };
    }
}