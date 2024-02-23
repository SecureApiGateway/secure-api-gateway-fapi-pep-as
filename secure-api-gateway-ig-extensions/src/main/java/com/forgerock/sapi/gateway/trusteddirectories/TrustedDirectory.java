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

import java.net.URL;

/**
 * A Trusted Directory is an external 'trust anchor' that the Secure API Gateway should trust to be the issuer
 * of software statements and the certificates associated with those statements. This interface allows access to
 * configuration information for a trusted directory. In the UK this is the Open Banking Directory, or the Open Banking
 * Sandbox Directory. It is trusted by both the ApiClient and the ApiProvider. In other eco-systems the registry will
 * be different. In some cases it can be a registry provided by the ApiProvider. For example a bank wishing to provide
 * innovative new custom APIs outside of a regulated system could create their own Trusted Registry.
 *
 * @see <a href="https://github.com/SecureApiGateway/SecureApiGateway/wiki/About-Dynamic-Client-Registration">
 *     About Dynamic Client Registration</a>
 */
public interface TrustedDirectory {
    /**
     * @return the value that can be expected to be found in the issuer field of Software Statements issued
     * by the Trusted Directory
     */
    String getIssuer();

    /**
     *
     * @return a String containing the jwks_uri against which software statement issued by this trusted directory
     * can be validated
     */
    URL getDirectoryJwksUri();

    /**
     * The software statement has a JWKS associated with it which contains the keys belonging to the particular software
     * statement.
     *
     * This property indicates whether the JWKS can be located via a URI in the software statement or whether the JWKS
     * is embedded in the statement.
     *
     * The JWKS URI approach is recommended as it allows for key rotation, the JWKS can be updated and changes will be
     * picked up the next time the URI is queried.
     *
     * @return true if the software statement contains the URI of the JWKS
     *         false if the software statement contains the JWKS embedded within it.
     */
    boolean softwareStatementHoldsJwksUri();
    /**
     *
     * @return If @link #softwareStatementHoldsJwksUri() returns true this method will return the name of the claim in the
     * software statement that holds the jwks_uri against which certificates associated with the software statement can
     * be found. If @link #softwareStatementHoldsJwksUri() returns false this will return null
     */
    String getSoftwareStatementJwksUriClaimName();


    /**
     * If @link #softwareStatementHoldsJwksUri() returns false this method will return the name of the Software Statement
     * claim in which the JWKS entry maybe found. If it returns true, this method will return null
     */
    String getSoftwareStatementJwksClaimName();

    /**
     *
     * @return the name of the claim in the software statement that holds a unique identifier for the organisation
     * to which the Software Statement belongs
     */
    String getSoftwareStatementOrgIdClaimName();

    /**
     *
     * @return the name of the claim in the software statement that holds the organisation name
     * to which the Software Statement belongs
     */
    String getSoftwareStatementOrgNameClaimName();

    /**
     *
     * @return the name of the claim in the software statement that holds a unique identifier for the software statement
     */
    String getSoftwareStatementSoftwareIdClaimName();

    /**
     * @return the name of the claim in the software statement that holds the array of redirect_uris registered for
     * the software statement
     */
    String getSoftwareStatementRedirectUrisClaimName();

    /**
     * @return the name of the claim in the software statement that holds the roles allocated to this software statement
     */
    String getSoftwareStatementRolesClaimName();

    /**
     * @return the name of the claim in the software statement that holds the name of the software client
     */
    String getSoftwareStatementClientNameClaimName();
}
