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

import static java.util.Objects.requireNonNull;
import static org.forgerock.util.Reject.unless;

import java.net.URI;

/**
 * Immutable {@link TrustedDirectory} implementation.
 */
public class DefaultTrustedDirectory implements TrustedDirectory {

    private final boolean disabled;
    private final URI directoryJwksUri;
    private final String issuer;
    private final String softwareStatementJwksUriClaimName;
    private final String softwareStatementJwksClaimName;
    private final String softwareStatementOrgIdClaimName;
    private final String softwareStatementOrgNameClaimName;
    private final String softwareStatementSoftwareIdClaimName;
    private final String softwareStatementRedirectUrisClaimName;
    private final String softwareStatementRolesClaimName;
    private final String softwareStatementClientNameClaimName;

    public static Builder builder() {
        return new Builder();
    }

    private DefaultTrustedDirectory(Builder builder) {
        this.disabled = builder.disabled;
        this.directoryJwksUri = builder.directoryJwksUri;
        this.issuer = builder.issuer;
        this.softwareStatementJwksUriClaimName = builder.softwareStatementJwksUriClaimName;
        this.softwareStatementJwksClaimName = builder.softwareStatementJwksClaimName;
        this.softwareStatementOrgIdClaimName = builder.softwareStatementOrgIdClaimName;
        this.softwareStatementOrgNameClaimName = builder.softwareStatementOrgNameClaimName;
        this.softwareStatementSoftwareIdClaimName = builder.softwareStatementSoftwareIdClaimName;
        this.softwareStatementRedirectUrisClaimName = builder.softwareStatementRedirectUrisClaimName;
        this.softwareStatementRolesClaimName = builder.softwareStatementRolesClaimName;
        this.softwareStatementClientNameClaimName = builder.softwareStatementClientNameClaimName;
    }

    @Override
    public boolean isDisabled() {
        return disabled;
    }

    @Override
    public URI getDirectoryJwksUri() {
        return directoryJwksUri;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public String getSoftwareStatementClientNameClaimName() {
        return softwareStatementClientNameClaimName;
    }

    public boolean softwareStatementHoldsJwksUri() {
        return softwareStatementJwksUriClaimName != null;
    }

    @Override
    public String getSoftwareStatementJwksClaimName() {
        return softwareStatementJwksClaimName;
    }

    @Override
    public String getSoftwareStatementJwksUriClaimName() {
        return softwareStatementJwksUriClaimName;
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
    public String getSoftwareStatementRedirectUrisClaimName() {
        return softwareStatementRedirectUrisClaimName;
    }

    @Override
    public String getSoftwareStatementRolesClaimName() {
        return softwareStatementRolesClaimName;
    }

    @Override
    public String getSoftwareStatementSoftwareIdClaimName() {
        return softwareStatementSoftwareIdClaimName;
    }

    public static class Builder {
        private boolean disabled;
        private URI directoryJwksUri;
        private String issuer;
        private String softwareStatementJwksUriClaimName;
        private String softwareStatementJwksClaimName;
        private String softwareStatementOrgIdClaimName;
        private String softwareStatementOrgNameClaimName;
        private String softwareStatementSoftwareIdClaimName;
        private String softwareStatementRedirectUrisClaimName;
        private String softwareStatementRolesClaimName;
        private String softwareStatementClientNameClaimName;

        public Builder setDirectoryJwksUri(URI directoryJwksUri) {
            this.directoryJwksUri = directoryJwksUri;
            return this;
        }

        public Builder setIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder setSoftwareStatementJwksUriClaimName(String softwareStatementJwksUriClaimName) {
            this.softwareStatementJwksUriClaimName = softwareStatementJwksUriClaimName;
            return this;
        }

        public Builder setSoftwareStatementJwksClaimName(String softwareStatementJwksClaimName) {
            this.softwareStatementJwksClaimName = softwareStatementJwksClaimName;
            return this;
        }

        public Builder setSoftwareStatementOrgIdClaimName(String softwareStatementOrgIdClaimName) {
            this.softwareStatementOrgIdClaimName = softwareStatementOrgIdClaimName;
            return this;
        }

        public Builder setSoftwareStatementOrgNameClaimName(String softwareStatementOrgNameClaimName) {
            this.softwareStatementOrgNameClaimName = softwareStatementOrgNameClaimName;
            return this;
        }

        public Builder setSoftwareStatementSoftwareIdClaimName(String softwareStatementSoftwareIdClaimName) {
            this.softwareStatementSoftwareIdClaimName = softwareStatementSoftwareIdClaimName;
            return this;
        }

        public Builder setSoftwareStatementRedirectUrisClaimName(String softwareStatementRedirectUrisClaimName) {
            this.softwareStatementRedirectUrisClaimName = softwareStatementRedirectUrisClaimName;
            return this;
        }

        public Builder setSoftwareStatementRolesClaimName(String softwareStatementRolesClaimName) {
            this.softwareStatementRolesClaimName = softwareStatementRolesClaimName;
            return this;
        }

        public Builder setSoftwareStatementClientNameClaimName(String softwareStatementClientNameClaimName) {
            this.softwareStatementClientNameClaimName = softwareStatementClientNameClaimName;
            return this;
        }

        public Builder setDisabled(boolean disabled) {
            this.disabled = disabled;
            return this;
        }

        public DefaultTrustedDirectory build() {
            requireNonNull(directoryJwksUri, "directoryJwksUri must be supplied");
            requireNonNull(issuer, "issuer must be supplied");
            unless(softwareStatementJwksUriClaimName != null ^ softwareStatementJwksClaimName != null,
                    "Exactly one of softwareStatementJwksUriClaimName or softwareStatementJwksClaimName must be supplied");
            requireNonNull(softwareStatementOrgIdClaimName, "softwareStatementOrgIdClaimName must be supplied");
            requireNonNull(softwareStatementOrgNameClaimName, "softwareStatementOrgNameClaimName must be supplied");
            requireNonNull(softwareStatementSoftwareIdClaimName, "softwareStatementSoftwareIdClaimName must be supplied");
            requireNonNull(softwareStatementRedirectUrisClaimName, "softwareStatementRedirectUrisClaimName must be supplied");
            requireNonNull(softwareStatementRolesClaimName, "softwareStatementRolesClaimName must be supplied");
            requireNonNull(softwareStatementClientNameClaimName, "softwareStatementClientNameClaimName must be supplied");

            return new DefaultTrustedDirectory(this);
        }
    }

}
