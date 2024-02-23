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

import java.net.MalformedURLException;
import java.net.URL;

public class TrustedDirectoryOpenBankingTest implements TrustedDirectory {

    /*
     * The value expected to be found in the issuer field of software statements issued by the Open Banking Test
     * directory
     */
    final static String issuer = "OpenBanking Ltd";


    final static boolean softwareStatementHoldsJwksUri = true;

    /*
     * The URL at which the Open Banking Test Directory JWKS are held, containing public certificates that may be used
     * to validate Open Banking Test directory issues Software Statements.
     */
    final static URL jwksUri;

    /*
     * The name of the claim in the Open Banking Test Directory issued software statement that holds the jwks_uri
     * against which certificates associated with this software statement may be validated
     */
    final static String softwareJwksUriClaimName = "software_jwks_endpoint";
    /*
     * The name of the claim in the Open Banking Test Directory issued software statement that holds a uid for the
     * organisation
     */
    final static String softwareStatementOrgIdClaimName = "org_id";
    /*
     * The name of the claim in the Open Banking Test Directory issued software statement that holds the
     * organisation name
     */
    final static String softwareStatementOrgNameClaimName = "org_name";
    /*
     * The name of the claim in the Open Banking Test Directory issued software statement that holds a uid for the
     * software statement
     */
    final static String softwareStatementSoftwareIdClaimName = "software_id";

    final static String softwareStatementRedirectUriClaimName = "software_redirect_uris";

    static final String softwareStatementRolesClaimName = "software_roles";

    static final String softwareStatementClientNameClaimName = "software_client_name";

    static {
        try {
            jwksUri = new URL("https://keystore.openbankingtest.org.uk/keystore/openbanking.jwks");
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public URL getDirectoryJwksUri() {
        return jwksUri;
    }

    @Override
    public boolean softwareStatementHoldsJwksUri() {
        return softwareStatementHoldsJwksUri;
    }

    @Override
    public String getSoftwareStatementJwksUriClaimName() {
        return softwareJwksUriClaimName;
    }

    @Override
    public String getSoftwareStatementJwksClaimName() {
        return null;
    }

    @Override
    public String getSoftwareStatementOrgIdClaimName() {
        return softwareStatementOrgIdClaimName;
    }

    @Override
    public String getSoftwareStatementOrgNameClaimName() {
        return softwareStatementOrgNameClaimName;
    }

    @Override
    public String getSoftwareStatementSoftwareIdClaimName() {
        return softwareStatementSoftwareIdClaimName;
    }

    @Override
    public String getSoftwareStatementRedirectUrisClaimName() {
        return softwareStatementRedirectUriClaimName;
    }

    @Override
    public String getSoftwareStatementRolesClaimName() {
        return softwareStatementRolesClaimName;
    }

    @Override
    public String getSoftwareStatementClientNameClaimName() {
        return softwareStatementClientNameClaimName;
    }
}
