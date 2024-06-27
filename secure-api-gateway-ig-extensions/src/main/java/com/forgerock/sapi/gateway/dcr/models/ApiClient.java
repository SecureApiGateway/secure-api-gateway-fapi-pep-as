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
package com.forgerock.sapi.gateway.dcr.models;

import java.net.URI;
import java.util.List;
import java.util.Objects;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.Reject;

/**
 * Data object which represents a registered OAuth2.0 client, this class is immutable.
 * <p>
 * Use {@link ApiClientBuilder} to create an instance.
 */
public class ApiClient {

    public static ApiClientBuilder builder() {
        return new ApiClientBuilder();
    }

    /**
     * The OAuth2.0 client_id for this client. This is generated and assigned at registration.
     * <p>
     * This ID can uniquely identify the ApiClient.
     */
    private final String oAuth2ClientId;

    /**
     * The Client ID for this client as defined in the software statement used to at registration (not necessarily unique).
     */
    private final String softwareClientId;

    /**
     * Name of the client
     */
    private final String clientName;

    /**
     * The URI of the JWKS which contains the certificates which can be used by this ApiClient for transport and
     * signing purposes.
     */
    private final URI jwksUri;

    /**
     * The JWK Set for this client
     */
    private final JWKSet jwks;

    /**
     * The Software Statement Assertions (SSA), which is a signed JWT containing the Software Statement registered.
     */
    private final SignedJwt softwareStatementAssertion;

    /**
     * The organisation that this client belongs to
     */
    private final ApiClientOrganisation organisation;

    /**
     * The roles allowed to be performed by this ApiClient.
     */
    private final List<String> roles;

    /**
     * Whether the ApiClient has been marked as deleted in the datastore.
     */
    private final boolean deleted;

    private ApiClient(ApiClientBuilder builder) {
        this.oAuth2ClientId = builder.oAuth2ClientId;
        this.softwareClientId = builder.softwareClientId;
        this.clientName = builder.clientName;
        this.jwksUri = builder.jwksUri;
        this.jwks = builder.jwks;
        this.softwareStatementAssertion = builder.softwareStatementAssertion;
        this.organisation = builder.organisation;
        this.roles = builder.roles;
        this.deleted = builder.deleted;
    }

    public String getOAuth2ClientId() {
        return oAuth2ClientId;
    }

    public String getSoftwareClientId() {
        return softwareClientId;
    }

    public String getClientName() {
        return clientName;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    public JWKSet getJwks() {
        return jwks;
    }

    public SignedJwt getSoftwareStatementAssertion() {
        return softwareStatementAssertion;
    }

    public ApiClientOrganisation getOrganisation() {
        return organisation;
    }

    public List<String> getRoles() {
        return roles;
    }

    public boolean isDeleted() {
        return deleted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final ApiClient apiClient = (ApiClient) o;
        return deleted == apiClient.deleted && Objects.equals(oAuth2ClientId, apiClient.oAuth2ClientId) && Objects.equals(softwareClientId, apiClient.softwareClientId) && Objects.equals(clientName, apiClient.clientName) && Objects.equals(jwksUri, apiClient.jwksUri) && Objects.equals(jwks, apiClient.jwks) && Objects.equals(softwareStatementAssertion, apiClient.softwareStatementAssertion) && Objects.equals(organisation, apiClient.organisation) && Objects.equals(roles, apiClient.roles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oAuth2ClientId, softwareClientId, clientName, jwksUri, jwks, softwareStatementAssertion, organisation, roles, deleted);
    }

    @Override
    public String toString() {
        return "ApiClient{" +
                "oAuth2ClientId='" + oAuth2ClientId + '\'' +
                ", softwareClientId='" + softwareClientId + '\'' +
                ", clientName='" + clientName + '\'' +
                ", jwksUri=" + jwksUri +
                ", jwks=" + jwks +
                ", softwareStatementAssertion=" + softwareStatementAssertion +
                ", organisation=" + organisation +
                ", roles=" + roles +
                ", deleted=" + deleted +
                '}';
    }

    public static class ApiClientBuilder {
        private String oAuth2ClientId;
        private String softwareClientId;
        private String clientName;
        private URI jwksUri;
        private JWKSet jwks;
        private List<String> roles;
        private SignedJwt softwareStatementAssertion;
        private ApiClientOrganisation organisation;
        private boolean deleted;

        public ApiClientBuilder oAuth2ClientId(String oAuth2ClientId) {
            this.oAuth2ClientId = oAuth2ClientId;
            return this;
        }

        public ApiClientBuilder softwareClientId(String softwareClientId) {
            this.softwareClientId = softwareClientId;
            return this;
        }

        public ApiClientBuilder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public ApiClientBuilder jwksUri(URI jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        public ApiClientBuilder jwks(JWKSet jwks){
            this.jwks = jwks;
            return this;
        }

        public ApiClientBuilder softwareStatementAssertion(SignedJwt softwareStatementAssertion) {
            this.softwareStatementAssertion = softwareStatementAssertion;
            return this;
        }

        public ApiClientBuilder organisation(ApiClientOrganisation organisation) {
            this.organisation = organisation;
            return this;
        }

        public ApiClientBuilder deleted(boolean deleted) {
            this.deleted = deleted;
            return this;
        }

        public ApiClientBuilder roles(List<String> roles){
            this.roles = roles;
            return this;
        }

        public ApiClient build() {
            Reject.ifNull(oAuth2ClientId, "oAuth2ClientId must be configured");
            Reject.ifNull(softwareClientId, "softwareClientId must be configured");
            Reject.ifNull(clientName, "clientName must be configured");
            Reject.ifNull(softwareStatementAssertion, "softwareStatementAssertion must be configured");
            Reject.ifNull(organisation, "organisation must be configured");
            Reject.ifNull(roles, "roles must be configured");
            Reject.unless(jwksUri == null ^ jwks == null, "Exactly one of jwksUri or jwks must be configured");
            return new ApiClient(this);
        }
    }
}
