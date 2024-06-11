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

import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;

public class TrustedDirectoryHeaplet extends GenericHeaplet {

    @Override
    public Object create() throws HeapException {
        return DefaultTrustedDirectory.builder()
                  .setDirectoryJwksUri(config.get("directoryJwksUri")
                                             .as(evaluatedWithHeapProperties())
                                             .required()
                                             .as(value -> URI.create(value.asString())))
                  .setIssuer(config.get("issuer")
                                   .as(evaluatedWithHeapProperties())
                                   .required()
                                   .asString())
                  .setSoftwareStatementJwksUriClaimName(config.get("softwareStatementJwksUriClaimName")
                                                              .as(evaluatedWithHeapProperties())
                                                              .asString())
                  .setSoftwareStatementJwksClaimName(config.get("softwareStatementJwksClaimName")
                                                           .as(evaluatedWithHeapProperties())
                                                           .asString())
                  .setSoftwareStatementOrgIdClaimName(config.get("softwareStatementOrgIdClaimName")
                                                            .as(evaluatedWithHeapProperties())
                                                            .required()
                                                            .asString())
                  .setSoftwareStatementOrgNameClaimName(config.get("softwareStatementOrgNameClaimName")
                                                              .as(evaluatedWithHeapProperties())
                                                              .required()
                                                              .asString())
                  .setSoftwareStatementSoftwareIdClaimName(config.get("softwareStatementSoftwareIdClaimName")
                                                                 .as(evaluatedWithHeapProperties())
                                                                 .required()
                                                                 .asString())
                  .setSoftwareStatementRedirectUrisClaimName(config.get("softwareStatementRedirectUrisClaimName")
                                                                   .as(evaluatedWithHeapProperties())
                                                                   .required()
                                                                   .asString())
                  .setSoftwareStatementRolesClaimName(config.get("softwareStatementRolesClaimName")
                                                            .as(evaluatedWithHeapProperties())
                                                            .required()
                                                            .asString())
                  .setSoftwareStatementClientNameClaimName(config.get("softwareStatementClientNameClaimName")
                                                                 .as(evaluatedWithHeapProperties())
                                                                 .required()
                                                                 .asString())
                  .setDisabled(config.get("disabled")
                                     .as(evaluatedWithHeapProperties())
                                     .defaultTo(Boolean.FALSE)
                                     .asBoolean())
                  .build();
    }
}
