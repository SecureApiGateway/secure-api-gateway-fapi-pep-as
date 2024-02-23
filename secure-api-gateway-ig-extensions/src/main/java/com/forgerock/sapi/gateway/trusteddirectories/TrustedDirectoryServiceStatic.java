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
import java.util.HashMap;
import java.util.Map;

/**
 * This class provides access to static config data. By static I mean the underlying classes hold Trusted Directory
 * configuration data that is hard coded. This class allows us to access this information via the TrustedDirectoryService
 * while we hone what needs to be in the Trusted Directory configuration data. Once we have settled on what data needs
 * to be held we can then create a TrustedDirectoryService that will read the Trusted Directory configuration from
 * a store such as Identity Manager in the FIdC.
 */
public class TrustedDirectoryServiceStatic implements TrustedDirectoryService {

    private final Map<String, TrustedDirectory> directoryConfigurations;

    /**
     * Constructor. The Secure API Gateway can itself be a trusted directory. This means it can issue software statements
     * and issue certificates associated with those software statements. This is useful for development and testing
     * but SHOULD NOT BE USED IN PRODUCTION. Whether the Secure API Gateway acts as a trusted directory or not is
     * controlled by the 'enableIGTestTrustedDirectory' parameter.
     * @param enableIGTestTrustedDirectory indicates if the Secure API Gateway should act as a Trusted Directory.</br>
     *                                     <b>NOTE: this should NOT be true in production deployments</b>
     * @param secureApiGatewayJwksUri The jwks_uri against which the signature of SSAs issued by the Trusted Directory
     *                                may be validated
     */
    public TrustedDirectoryServiceStatic(Boolean enableIGTestTrustedDirectory, URL secureApiGatewayJwksUri) {
        directoryConfigurations = new HashMap<>();

        addOpenBankingTestTrustedDirectory();
        if(enableIGTestTrustedDirectory) {
            addGatewayTestTrustedDirectory(secureApiGatewayJwksUri);
        }
    }

    /**
     *
     * @param issuer - the value of the 'iss' field that is used by the Trusted Directory in Software Statement
     *               Assertions. For the Open Banking Directories for example, this will be "OpenBanking Ltd"
     * @return The {@code TrustedDirectory} associated with the issuer or null if no value is held for the provided
     * issuer
     */
    @Override
    public TrustedDirectory getTrustedDirectoryConfiguration(String issuer) {
        return directoryConfigurations.get(issuer);
    }

    private void addGatewayTestTrustedDirectory(URL testDirectoryFQDN) {
        TrustedDirectory secureApiGatewayTrustedDirectory = new TrustedDirectorySecureApiGateway(testDirectoryFQDN);
        directoryConfigurations.put(secureApiGatewayTrustedDirectory.getIssuer(), secureApiGatewayTrustedDirectory);
    }

    private void addOpenBankingTestTrustedDirectory() {
        TrustedDirectory openBankingTestDirectory =  new TrustedDirectoryOpenBankingTest();
        directoryConfigurations.put(openBankingTestDirectory.getIssuer(), openBankingTestDirectory);
    }
}
