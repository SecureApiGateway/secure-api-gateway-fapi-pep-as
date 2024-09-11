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

import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.util.List;
import java.util.function.Supplier;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.forgerock.sapi.gateway.jwks.JwkSetService;

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
     * Name of the client.
     */
    private final String clientName;

    /**
     * Supplier of the client's JWKSet.
     */
    private final Supplier<Promise<JWKSet, FailedToLoadJWKException>> jwkSetSupplier;

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
        this.jwkSetSupplier = builder.jwkSetSupplier;
        this.softwareStatementAssertion = builder.softwareStatementAssertion;
        this.organisation = builder.organisation;
        this.roles = unmodifiableList(builder.roles);
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

    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet() {
        return jwkSetSupplier.get();
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
    public String toString() {
        return "ApiClient{" +
                "oAuth2ClientId='" + oAuth2ClientId + '\'' +
                ", softwareClientId='" + softwareClientId + '\'' +
                ", clientName='" + clientName + '\'' +
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
        private List<String> roles;
        private SignedJwt softwareStatementAssertion;
        private ApiClientOrganisation organisation;
        private boolean deleted;
        private Supplier<Promise<JWKSet, FailedToLoadJWKException>> jwkSetSupplier;

        public ApiClientBuilder() {
        }

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

        /**
         * Configures the jwkSetSupplier to use an embedded JWKS.
         *
         * @param jwkSet the JWKSet for the supplier to return
         * @return the builder
         */
        public ApiClientBuilder withEmbeddedJwksSupplier(JWKSet jwkSet) {
            requireNonNull(jwkSet, "jwkSet must be provided");
            this.jwkSetSupplier = () -> Promises.newResultPromise(jwkSet);
            return this;
        }

        /**
         * Configures the jwkSetSupplier to retrieve the {@link JWKSet} using the {@link JwkSetService}.
         *
         * @param jwksUri the location of the {@link JWKSet}
         * @param jwkSetService the service to use to retrieve the {@link JWKSet}
         * @return the builder
         */
        public ApiClientBuilder withUriJwksSupplier(URI jwksUri, JwkSetService jwkSetService) {
            requireNonNull(jwksUri, "jwksUri must be provided");
            requireNonNull(jwkSetService, "jwkSetService must be provided");
            this.jwkSetSupplier = () -> jwkSetService.getJwkSet(jwksUri);
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
            requireNonNull(oAuth2ClientId, "oAuth2ClientId must be configured");
            requireNonNull(softwareClientId, "softwareClientId must be configured");
            requireNonNull(clientName, "clientName must be configured");
            requireNonNull(softwareStatementAssertion, "softwareStatementAssertion must be configured");
            requireNonNull(organisation, "organisation must be configured");
            requireNonNull(roles, "roles must be configured");
            requireNonNull(jwkSetSupplier, "jwkSetSupplier must be configured - please call withUriJwksSupplier or withEmbeddedJwksSupplier");
            return new ApiClient(this);
        }
    }
}
