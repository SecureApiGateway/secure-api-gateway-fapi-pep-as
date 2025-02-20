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
package com.forgerock.sapi.gateway.common.jwt;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClaimsSetFacadeTest {

    private ClaimsSetFacade claimSet;

    @BeforeEach
    void setUp() throws MalformedURLException {
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("claim1", "value1",
                "claim2", new URL("https://acme.com"), "iss", "jwt issuer",
                "jwks_uri", "https://jwks.com"));
        claimSet = new ClaimsSetFacade(claimsSet);
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void success_getStringClaim() throws JwtException {
        // Given
        // When
        String claim1Value = claimSet.getStringClaim("claim1");
        // Then
        assertThat(claim1Value).isEqualTo("value1");
    }

    @Test
    void throwsWhenClaimNotString_getStringClaim() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() -> claimSet.getStringClaim("claim2"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getStringClaim() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() -> claimSet.getStringClaim("claim3"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenInvalidArgument_getStringClaim() {
        // Given
        // When
        IllegalArgumentException exception = catchThrowableOfType(() -> claimSet.getStringClaim(""),
                IllegalArgumentException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getStringClaimAsURL() throws JwtException {
        // Given
        // When
        URI claimValue = claimSet.getStringClaimAsURI("jwks_uri");
        // Then
        assertThat(claimValue).isNotNull();
    }

    @Test
    void throwsWhenClaimNotUrl_getStringClaimAsURL() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() ->claimSet.getStringClaimAsURI("@~}~@}"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getStringClaimAsURL() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() ->claimSet.getStringClaimAsURI("nonexistant"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenInvalidArgument_getStringClaimAsURL() {
        // Given
        // When
        IllegalArgumentException exception = catchThrowableOfType(() ->claimSet.getStringClaimAsURI(""),
                IllegalArgumentException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getJsonValueClaim() throws JwtException {
        // Given
        // When
        JsonValue value = claimSet.getJsonValueClaim("claim1");
        // Then
        assertThat(value).isNotNull();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getJsonValueClaim() {
        // Given
        // When
        JwtException exception  = catchThrowableOfType(()->claimSet.getJsonValueClaim("nonExistent"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenInvalidArgument_getJsonValueClaim() {
        // Given
        // When
        IllegalArgumentException exception  = catchThrowableOfType(()->claimSet.getJsonValueClaim(""),
                IllegalArgumentException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getIssuer() throws JwtException {
        // Given
        // WHen
        String issuer = claimSet.getIssuer();
        // Then
        assertThat(issuer).isNotNull();
        assertThat(issuer).isNotEmpty();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getIssuer(){
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of());
        ClaimsSetFacade emptyClaimSet = new ClaimsSetFacade(claimsSet);
        // When
        JwtException exception = catchThrowableOfType(emptyClaimSet::getIssuer, JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getRequiredStringListClaim() throws JwtException {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of("code id_token")));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        List<String> responseTypes =  claimsSetFacade.getRequiredStringListClaim("response_type");

        // Then
        assertThat(responseTypes).isNotNull();
        assertThat(responseTypes.contains("code id_token")).isTrue();
    }

    @Test
    void fail_claimDoesNotExist_getRequiredStringListClaim() {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet();
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        JwtException exception =  catchThrowableOfType(()->claimsSetFacade.getRequiredStringListClaim("response_type"), JwtException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Jwt claim 'response_type' not defined");
    }

    @Test
    void fail_claimIsNotList_getRequiredStringListClaim() {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", "code id_token"));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        JwtException exception =  catchThrowableOfType(()->claimsSetFacade.getRequiredStringListClaim("response_type"), JwtException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Jwt claim 'response_type' is not of type List");
    }

    @Test
    void fail_listIsNotStrings_getRequiredStringListClaim() {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of(1, 2, 3)));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        JwtException exception =  catchThrowableOfType(()->claimsSetFacade.getRequiredStringListClaim("response_type"), JwtException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Jwt claim 'response_type' is not a List of Strings");
    }

    @Test
    void success_noSuchClaim_getOptionStringListClaim() throws JwtException {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet();
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        Optional<List<String>> values = claimsSetFacade.getOptionalStringListClaim("response_type");

        // Then
        assertThat(values).isNotNull();
        assertThat(values.isEmpty()).isTrue();
    }

    @Test
    void success_claimExists_getOptionStringListClaim() throws JwtException {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of("code id_token")));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        Optional<List<String>> values = claimsSetFacade.getOptionalStringListClaim("response_type");

        // Then
        assertThat(values).isNotNull();
        assertThat(values.isEmpty()).isFalse();
        assertThat(values.get().contains("code id_token")).isTrue();
    }

    @Test
    void success_setStringListClaim() throws JwtException {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet();
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        List<String> expectedResponseTypes = List.of("code", "code id_token");
        claimsSetFacade.setStringArrayClaim("response_type", expectedResponseTypes);

        // Then
        Optional<List<String>> responseTypeValues = claimsSetFacade.getOptionalStringListClaim("response_type");
        assertThat(responseTypeValues.isPresent()).isTrue();
        assertThat(responseTypeValues.get()).isEqualTo(expectedResponseTypes);
    }

    @Test
    void success_overwriteStringListClaim() throws JwtException {
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of("code id_token")));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        List<String> expectedResponseTypes = List.of("code1", "code1 id_token1");
        claimsSetFacade.setStringArrayClaim("response_type", expectedResponseTypes);

        // Then
        Optional<List<String>> responseTypeValues = claimsSetFacade.getOptionalStringListClaim("response_type");
        assertThat(responseTypeValues.isPresent()).isTrue();
        assertThat(responseTypeValues.get()).isEqualTo(expectedResponseTypes);
    }

    @Test
    void success_getRequiredUriList() throws JwtException {

        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of("https://domain1.com/callback", "https://domain2.com/callback")));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        List<URI> responseTypes =  claimsSetFacade.getRequiredUriListClaim("response_type");

        // Then
        assertThat(responseTypes).isNotNull();
        assertThat(responseTypes.size()).isEqualTo(2);
        assertThat(responseTypes.get(0).toString()).isEqualTo("https://domain1.com/callback");
    }

    @Test
    void fail_getRequiredUriList_NotURLs() {

        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of("@~}[hello", "there")));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        JwtException exception =  catchThrowableOfType(()->claimsSetFacade.getRequiredUriListClaim("response_type"),
                JwtException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).contains("claim of name 'response_type' is expected to hold valid URIs:");
    }

    @Test
    void fail_getRequiredUriList_NotStrings() {

        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", List.of(1.0f, 3.2f)));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        JwtException exception =  catchThrowableOfType(()->claimsSetFacade.getRequiredUriListClaim("response_type"),
                JwtException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).contains("claim of name 'response_type' is not a List of Strings");
    }

    @Test
    void fail_getRequiredUriList_NotList() {

        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("response_type", "https://doamin1.com/callback"));
        ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(claimsSet);

        // When
        JwtException exception =  catchThrowableOfType(()->claimsSetFacade.getRequiredUriListClaim("response_type"),
                JwtException.class);

        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).contains("claim of name 'response_type' is not of type List");
    }
}