/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.filter.RegistrationRequestRoleBasedScopeValidationFilter.ROLE_AISP;
import static com.forgerock.sapi.gateway.dcr.filter.RegistrationRequestRoleBasedScopeValidationFilter.ROLE_CBPII;
import static com.forgerock.sapi.gateway.dcr.filter.RegistrationRequestRoleBasedScopeValidationFilter.ROLE_PISP;
import static com.forgerock.sapi.gateway.dcr.filter.RegistrationRequestRoleBasedScopeValidationFilter.SCOPE_ACCOUNTS;
import static com.forgerock.sapi.gateway.dcr.filter.RegistrationRequestRoleBasedScopeValidationFilter.SCOPE_FUNDS;
import static com.forgerock.sapi.gateway.dcr.filter.RegistrationRequestRoleBasedScopeValidationFilter.SCOPE_PAYMENTS;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Status.OK;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_CLIENT_METADATA;
import static org.forgerock.openig.fapi.dcr.common.ErrorCode.INVALID_SOFTWARE_STATEMENT;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.fapi.dcr.SoftwareStatement;
import org.forgerock.openig.fapi.dcr.common.ErrorCode;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequest;
import org.forgerock.openig.fapi.dcr.request.RegistrationRequestFapiContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RegistrationRequestRoleBasedScopeValidationFilterTest {

    @Mock
    private RegistrationRequest mockRegistrationRequest;
    @Mock
    private SoftwareStatement softwareStatement;
    @Mock
    Handler next;
    private final Filter scopeValidationFilter = new RegistrationRequestRoleBasedScopeValidationFilter();
    private Context context;
    private Request request;

    static Stream<Arguments> validScopesAndSsaRoles() {
        return Stream.of(
                // Payments scope, where SSA has PISP (payments) role
                arguments(List.of(SCOPE_PAYMENTS),
                          List.of(ROLE_AISP, ROLE_PISP)),
                // Accounts scope, where SSA has AISP (accounts) role
                arguments(List.of(SCOPE_ACCOUNTS),
                          List.of(ROLE_AISP, ROLE_PISP)),
                // Funds scope, where SSA has CBPII (funds) role
                arguments(List.of(SCOPE_FUNDS),
                          List.of(ROLE_CBPII, ROLE_PISP)));
    }

    @BeforeEach
    void setUp() {
        context = new RegistrationRequestFapiContext(new RootContext(), mockRegistrationRequest);
        request = new Request().setMethod("POST");
    }

    @ParameterizedTest
    @MethodSource("validScopesAndSsaRoles")
    void shouldValidateScopesAndSsaRoles(final List<String> scopes, final List<String> ssaRoles) {
        //Given
        when(mockRegistrationRequest.getScope()).thenReturn(String.join(" ", scopes));
        when(mockRegistrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getRoles()).thenReturn(ssaRoles);
        when(next.handle(context, request)).thenReturn(newResponsePromise(new Response(OK)));
        // When/ Then
        Response response = scopeValidationFilter.filter(context, request, next).getOrThrowIfInterrupted();
        assertThat(response.getStatus()).isEqualTo(OK);
    }

    static Stream<Arguments> invalidScopesAndSsaRoles() {
        return Stream.of(
                // Payments scope, but SSA does not have PISP (payments) role
                arguments(List.of(SCOPE_PAYMENTS),
                          List.of(ROLE_AISP, ROLE_CBPII),
                          INVALID_CLIENT_METADATA,
                          "contains scopes (%s) not allowed for the presented software statement (%s)"
                                  .formatted(SCOPE_PAYMENTS, ROLE_PISP)),
                // Accounts scope, but SSA does not have AISP (accounts) role
                arguments(List.of(SCOPE_ACCOUNTS),
                          List.of(ROLE_PISP, ROLE_CBPII),
                          INVALID_CLIENT_METADATA,
                          "contains scopes (%s) not allowed for the presented software statement (%s)"
                                  .formatted(SCOPE_ACCOUNTS, ROLE_AISP)),
                // Funds scope, but SSA does not have CBPII (funds) role
                arguments(List.of(SCOPE_FUNDS),
                          List.of(ROLE_AISP, ROLE_PISP),
                          INVALID_CLIENT_METADATA,
                          "contains scopes (%s) not allowed for the presented software statement (%s)"
                                  .formatted(SCOPE_FUNDS, ROLE_CBPII)));
    }

    @ParameterizedTest
    @MethodSource("invalidScopesAndSsaRoles")
    void shouldFailWithIncompatibleScopesAndSsaRoles(final List<String> scopes,
                                                     final List<String> ssaRoles,
                                                     final ErrorCode expectedErrorCode,
                                                     final String expectedErrorMessage) throws IOException {
        //Given
        when(mockRegistrationRequest.getScope()).thenReturn(String.join(" ", scopes));
        when(mockRegistrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getRoles()).thenReturn(ssaRoles);
        // When
        Response response = scopeValidationFilter.filter(context, request, next).getOrThrowIfInterrupted();
        // Then
        verifyNoInteractions(next);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies(errorResponseJson -> {
                    assertThat(errorResponseJson.get("error").asString()).isEqualTo(expectedErrorCode.toString());
                    assertThat(errorResponseJson.get("error_description").asString()).contains(expectedErrorMessage);
                });
    }

    @Test
    void shouldFailIfNoScopesSupplied() throws IOException {
        // Given - empty SSA roles (optional, but not null)
        when(mockRegistrationRequest.getScope()).thenReturn(SCOPE_PAYMENTS);
        when(mockRegistrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(softwareStatement.getRoles()).thenReturn(emptyList());
        // When
        Response response = scopeValidationFilter.filter(context, request, next).getOrThrowIfInterrupted();
        // Then
        verifyNoInteractions(next);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies(errorResponseJson -> {
                    assertThat(errorResponseJson.get("error").asString())
                            .isEqualTo(INVALID_SOFTWARE_STATEMENT.toString());
                    assertThat(errorResponseJson.get("error_description").asString())
                            .contains("The software_statement jwt does not contain a 'software_roles' claim");
                });
    }

    @Test
    void shouldFailIfNoSsaRoles() throws IOException {
        // Given - no scope supplied on request
        when(mockRegistrationRequest.getScope()).thenReturn(null);
        // When
        Response response = scopeValidationFilter.filter(context, request, next).getOrThrowIfInterrupted();
        // Then
        verifyNoInteractions(next);
        assertThat(response.getEntity().getJson())
                .asInstanceOf(type(JsonValue.class))
                .satisfies(errorResponseJson -> {
                    assertThat(errorResponseJson.get("error").asString())
                            .isEqualTo(INVALID_CLIENT_METADATA.toString());
                    assertThat(errorResponseJson.get("error_description").asString())
                            .contains("The request jwt does not contain the required scopes claim");
                });
    }
}