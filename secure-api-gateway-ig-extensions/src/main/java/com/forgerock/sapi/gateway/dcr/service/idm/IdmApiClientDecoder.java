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
package com.forgerock.sapi.gateway.dcr.service.idm;

import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.util.List;

import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.SignedJwt;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.ApiClient.ApiClientBuilder;
import com.forgerock.sapi.gateway.dcr.models.ApiClientOrganisation;
import com.forgerock.sapi.gateway.jwks.JwkSetService;

/**
 * Decodes an {@link ApiClient} from a {@link JsonValue} returned by IDM
 */
public class IdmApiClientDecoder {

    /**
     * JwkSetService used to obtain the ApiClient's {@link JWKSet} when it is stored in a remote location.
     */
    private final JwkSetService jwkSetService;

    public IdmApiClientDecoder(final JwkSetService jwkSetService) {
        this.jwkSetService = requireNonNull(jwkSetService, "jwkSetService must be provided");
    }

    /**
     * Decodes a json into an ApiClient.
     * <p>
     * This method will throw a RuntimeException if decoding fails, for example if a required field is missing or if
     * there is a datatype mismatch.
     *
     * @param apiClientJson the json to decode
     * @return ApiClient
     * @throws JsonValueException if decoding the json fails
     */
    public ApiClient decode(JsonValue apiClientJson) {
        try {
            final ApiClientBuilder apiClientBuilder = ApiClient.builder()
                    .clientName(apiClientJson.get("name").as(this::requiredField).asString())
                    .oAuth2ClientId(apiClientJson.get("oauth2ClientId").as(this::requiredField).asString())
                    .softwareClientId(apiClientJson.get("id").as(this::requiredField).asString())
                    .deleted(apiClientJson.get("deleted").as(this::requiredField).asBoolean())
                    .softwareStatementAssertion(apiClientJson.get("ssa").as(this::requiredField).as(this::decodeSsa))
                    .organisation(apiClientJson.get("apiClientOrg").as(this::requiredField).as(this::decodeApiClientOrganisation))
                    .roles(apiClientJson.get("roles").as(this::requiredField).as(this::decodeRoles));

            final JsonValue jwksUriValue = apiClientJson.get("jwksUri");
            if (jwksUriValue.isNotNull()) {
                apiClientBuilder.withUriJwksSupplier(jwksUriValue.as(jwks -> URI.create(jwks.asString())),
                                                     jwkSetService);
            }

            final JsonValue jwks = apiClientJson.get("jwks");
            if (jwks.isNotNull()){
                apiClientBuilder.withEmbeddedJwksSupplier(this.decodeJwks(jwks));
            }
            return apiClientBuilder.build();
        } catch (JsonValueException jve) {
            // These errors are expected and contain enough information to understand what when wrong e.g. missing required field
            throw jve;
        } catch (RuntimeException ex) {
            // Unexpected decode exception, dump the raw json to provide additional debug info
            throw new IllegalStateException("Unexpected exception thrown decoding apiClient, raw json: " + apiClientJson, ex);
        }
    }

    private JWKSet decodeJwks(JsonValue jwks) {
        return JWKSet.parse(jwks);
    }

    private List<String> decodeRoles(JsonValue jsonValue) {
        if (!jsonValue.isList()) {
            throw new JsonValueException(jsonValue, "Expecting a List of java.lang.String elements");
        }
        return jsonValue.asList(String.class);
    }

    /**
     * Helper transformationFunction which validates that a particular field has a value.
     * If the field is null then a JsonValueException will be raised.
     */
    private JsonValue requiredField(JsonValue jsonValue) throws JsonValueException {
        if (jsonValue.isNull()) {
            throw new JsonValueException(jsonValue, "is a required field, failed to decode IDM ApiClient");
        }
        return jsonValue;
    }

    private SignedJwt decodeSsa(JsonValue ssa) {
        final String jwtString = ssa.asString();
        try {
            return new JwtReconstruction().reconstructJwt(jwtString, SignedJwt.class);
        } catch (RuntimeException rte) {
            throw new JsonValueException(ssa, "failed to decode JWT, raw jwt string: " + jwtString, rte);
        }
    }

    private ApiClientOrganisation decodeApiClientOrganisation(JsonValue org) {
        final String orgId = org.get("id").as(this::requiredField).asString();
        final String orgName = org.get("name").as(this::requiredField).asString();
        return new ApiClientOrganisation(orgId, orgName);
    }
}