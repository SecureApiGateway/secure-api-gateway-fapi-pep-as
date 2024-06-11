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
package com.forgerock.sapi.gateway.fapi.v1;

import static com.forgerock.sapi.gateway.util.CryptoUtils.convertToPem;
import static com.forgerock.sapi.gateway.util.CryptoUtils.createEncodedJwtString;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateExpiredX509Cert;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.jwt.ClaimsSetFacade;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.common.Validator;
import com.forgerock.sapi.gateway.dcr.common.exceptions.ValidationException;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest.Builder;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatementTestFactory;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.fapi.v1.FapiAdvancedDCRValidationFilter.Heaplet;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.mtls.HeaderCertificateRetriever;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jose.JWSAlgorithm;

class FapiAdvancedDCRValidationFilterTest {

    private static final String CERT_HEADER_NAME = "x-cert";

    private static final String TEST_CERT_PEM = convertToPem(generateX509Cert(generateRsaKeyPair(), "CN=fapitest"));
    private static final JwtDecoder JWT_DECODER = new JwtDecoder();
    private static final HeapImpl EMPTY_HEAP = new HeapImpl(Name.of("testHeap"));

    private static Map<String, Object> VALID_REG_REQUEST_CLAIMS;
    private static RegistrationRequest VALID_REG_REQUEST;

    private TestSuccessResponseHandler successHandler;

    private FapiAdvancedDCRValidationFilter fapiValidationFilter;

    @BeforeAll
    public static void beforeAll() throws DCRRegistrationRequestBuilderException {
        final Map<String, Object> ssaClaims = SoftwareStatementTestFactory.getValidJwksBasedSsaClaims(Map.of());
        final String ssaJwt = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        VALID_REG_REQUEST_CLAIMS = Map.of("iss", "ACME Fintech",
                                       "token_endpoint_auth_method", "private_key_jwt",
                                       "scope", "openid accounts payments",
                                       "redirect_uris", List.of("https://google.co.uk"),
                                       "response_types", List.of("code id_token"),
                                       "token_endpoint_auth_signing_alg", "PS256",
                                       "id_token_signed_response_alg", "PS256",
                                       "request_object_signing_alg", "PS256",
                                       "software_statement", ssaJwt);

        VALID_REG_REQUEST = createRegistrationRequest(VALID_REG_REQUEST_CLAIMS);
    }

    private static RegistrationRequest createRegistrationRequest(Map<String, Object> claims) throws DCRRegistrationRequestBuilderException {
        final SoftwareStatement.Builder softwareStatementBuilder = new SoftwareStatement.Builder(
                TrustedDirectoryTestFactory.getTrustedDirectoryService(), JWT_DECODER);

        final Builder registrationRequestBuilder = new Builder(softwareStatementBuilder, JWT_DECODER);

        return registrationRequestBuilder.build(createEncodedJwtString(claims, JWSAlgorithm.PS256));
    }

    @BeforeEach
    public void beforeEach() throws HeapException {
        fapiValidationFilter = createDefaultFapiFilter();
        successHandler = new TestSuccessResponseHandler();
    }

    /**
     * Uses the Heaplet to create a FapiAdvancedDCRValidationFilter with the default configuration.
     */
    private static FapiAdvancedDCRValidationFilter createDefaultFapiFilter() throws HeapException {
        final JsonValue filterConfig = json(object(field("clientTlsCertHeader", CERT_HEADER_NAME)));
        return (FapiAdvancedDCRValidationFilter) new FapiAdvancedDCRValidationFilter.Heaplet()
                                                                                    .create(Name.of("fapiTest"),
                                                                                            filterConfig, EMPTY_HEAP);
    }

    private void validateErrorResponse(Response response, DCRErrorCode expectedErrorCode, String expectedErrorDescription) {
        assertEquals(Status.BAD_REQUEST, response.getStatus());
        assertEquals("application/json; charset=UTF-8", response.getHeaders().getFirst(ContentTypeHeader.class));
        try {
            final JsonValue errorResponseBody = (JsonValue) response.getEntity().getJson();
            assertEquals(expectedErrorCode.getCode(), errorResponseBody.get("error").asString());
            assertEquals(expectedErrorDescription, errorResponseBody.get("error_description").asString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void submitRequestAndValidateSuccessful(String httpMethod, FapiAdvancedDCRValidationFilter filter) throws Exception {
        final Request request = new Request().setMethod(httpMethod);
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(TEST_CERT_PEM, StandardCharsets.UTF_8)));

        final Context context = createContext(VALID_REG_REQUEST);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        if (!response.getStatus().isSuccessful()) {
            fail("Expected a successful response instead got: " + response.getStatus() + ", entity: " + response.getEntity().getJson());
        }
        assertTrue(successHandler.hasBeenInteractedWith(), "Filter was expected to pass the request on to the successHandler");
    }

    private static Context createContext(RegistrationRequest registrationRequest) {
        final AttributesContext attributesContext = new AttributesContext(new RootContext());
        attributesContext.getAttributes().put(RegistrationRequest.REGISTRATION_REQUEST_KEY, registrationRequest);
        return new TransactionIdContext(attributesContext, new TransactionId("1234"));
    }

    /**
     * Tests for the individual validators which validate particular fields within the Registration Request JWT.
     */
    @Nested
    class RegistrationRequestObjectFieldValidatorTests {

        private <T> void runValidationAndVerifyExceptionThrown(Validator<RegistrationRequest> validator,
                RegistrationRequest registrationRequest, DCRErrorCode expectedErrorCode, String expectedErrorMessage) {
            final ValidationException validationException = Assertions.assertThrows(ValidationException.class,
                    () -> validator.validate(registrationRequest));
            assertEquals(expectedErrorCode, validationException.getErrorCode(), "errorCode field");
            assertEquals(expectedErrorMessage, validationException.getErrorDescription(), "errorMessage field");
        }

        @Test
        void failsWhenRedirectUrisArrayEmpty() {
            final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
            when(registrationRequest.getRedirectUris()).thenReturn(List.of());
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, registrationRequest,
                    DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris array must not be empty");
        }

        @Test
        void failsWhenRedirectUrisNonHttpsUri() {
            final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
            final List<URI> uris = Stream.of("https://www.google.com", "http://www.google.co.uk").map(URI::create).toList();
            when(registrationRequest.getRedirectUris()).thenReturn(uris);
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, registrationRequest,
                    DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris must use https scheme");
        }

        @Test
        void failsWhenRedirectUrisContainsLocalhost() {
            final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
            final List<URI> uris = Stream.of("https://www.google.com", "https://localhost:8080/blah").map(URI::create).toList();
            when(registrationRequest.getRedirectUris()).thenReturn(uris);
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, registrationRequest,
                    DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris must not contain localhost");
        }

        @Test
        void validRedirectUris() {
            final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
            final List<URI> uris = Stream.of("https://www.google.com", "https://www.google.co.uk").map(URI::create).toList();
            when(registrationRequest.getRedirectUris()).thenReturn(uris);
            fapiValidationFilter.validateRedirectUris(registrationRequest);
        }

        @Test
        void failsWhenTokenEndpointAuthMethodFieldMissing() {
            final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
            when(registrationRequest.getClaimsSet()).thenReturn(new ClaimsSetFacade(new JwtClaimsSet(Map.of())));
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateTokenEndpointAuthMethods, registrationRequest,
                    DCRErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: token_endpoint_auth_method");
        }

        @Test
        void failsWhenTokenEndpointAuthMethodValueNotSupported() {
            final String[] invalidAuthMethods = new String[]{"none", "client_secret"};
            for (String invalidAuthMethod : invalidAuthMethods) {
                final RegistrationRequest registrationRequest = mockRegistrationRequest(Map.of("token_endpoint_auth_method", invalidAuthMethod));
                runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateTokenEndpointAuthMethods, registrationRequest,
                        DCRErrorCode.INVALID_CLIENT_METADATA, "token_endpoint_auth_method not supported, must be one of: [private_key_jwt, self_signed_tls_client_auth, tls_client_auth]");
            }
        }

        @Test
        void tokenEndpointAuthMethodValid() {
            final String[] validMethods = new String[]{"private_key_jwt", "self_signed_tls_client_auth", "tls_client_auth"};
            for (String validAuthMethod : validMethods) {
                final Map<String, Object> claims = Map.of("token_endpoint_auth_method", validAuthMethod);
                final RegistrationRequest registrationRequest = mockRegistrationRequest(claims);

                fapiValidationFilter.validateTokenEndpointAuthMethods(registrationRequest);
            }
        }

        @Test
        void signingAlgorithmFieldsMissingAreSkipped() {
            final List<String> signingAlgoFields = List.of("token_endpoint_auth_signing_alg", "id_token_signed_response_alg",
                                                           "request_object_signing_alg");

            // Test submitting requests which each omit one of the fields in turn
            for (String fieldToOmit : signingAlgoFields) {
                final Map<String, Object> signingFields = new HashMap<>();
                 signingAlgoFields.stream()
                                  .filter(field -> !field.equals(fieldToOmit))
                                  .forEach(field -> signingFields.put(field, "PS256"));
                final RegistrationRequest registrationRequest = mockRegistrationRequest(signingFields);
                fapiValidationFilter.validateSigningAlgorithmUsed(registrationRequest);
            }
        }

        @Test
        void failsWhenSigningAlgorithmFieldsUnsupportedAlgo() {
            final List<String> signingAlgoFields = List.of("token_endpoint_auth_signing_alg", "id_token_signed_response_alg",
                    "request_object_signing_alg");

            // Test submitting requests which each set one of the fields to an invalid algorithm in turn
            for (String invalidAlgoField : signingAlgoFields) {
                Map<String, Object> signingFields = new HashMap<>();
                signingAlgoFields.stream().filter(field -> !field.equals(invalidAlgoField)).forEach(field -> signingFields.put(field, "PS256"));
                signingFields.put(invalidAlgoField, "RS256");
                runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateSigningAlgorithmUsed, mockRegistrationRequest(signingFields),
                        DCRErrorCode.INVALID_CLIENT_METADATA, "request object field: " + invalidAlgoField + ", must be one of: [ES256, PS256]");
            }
        }

        @Test
        void signingAlgorithmFieldsValid() {
            final Map<String, Object> claims = Stream.of("token_endpoint_auth_signing_alg",
                                                                 "id_token_signed_response_alg",
                                                                 "request_object_signing_alg")
                                                     .collect(toMap(identity(), ignore -> "PS256"));
            fapiValidationFilter.validateSigningAlgorithmUsed(mockRegistrationRequest(claims));
        }

        @Test
        void failsWhenResponseTypeFieldMissing() {
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, mock(RegistrationRequest.class),
                    DCRErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: response_types");
        }

        @Test
        void responseTypesFieldValid() {
            List<List<String>> validResponseTypeValues = List.of(List.of("code"),
                                                                 List.of("code id_token"),
                                                                 List.of("id_token code"),
                                                                 List.of("code", "code id_token"),
                                                                 List.of("id_token code", "code"));

            for (List<String> validResponseTypeValue : validResponseTypeValues) {
                final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
                when(registrationRequest.getResponseTypes()).thenReturn(Optional.of(validResponseTypeValue));

                fapiValidationFilter.validateResponseTypes(registrationRequest);
            }
        }

        @Test
        void failsWhenResponseTypesInvalid() {
            final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
            when(registrationRequest.getResponseTypes()).thenReturn(Optional.of(List.of("blah")));

            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, registrationRequest,
                    DCRErrorCode.INVALID_CLIENT_METADATA, "Invalid response_types value: blah, must be one of: \"code\" or \"code id_token\"");
        }
    }

    private static RegistrationRequest mockRegistrationRequest(Map<String, Object> claims) {
        final RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
        final ClaimsSetFacade claimsSetFacade = new ClaimsSetFacade(new JwtClaimsSet(claims));
        when(registrationRequest.getClaimsSet()).thenReturn(claimsSetFacade);
        when(registrationRequest.getResponseTypes()).thenCallRealMethod();
        return registrationRequest;
    }

    /**
     * Tests which invoke the Filter's filter method, passing HTTP Request and Context objects and validate the
     * HTTP Response is valid.
     */
    @Nested
    class FilterHttpRequestTests {

        @Test
        void validRequest() throws Exception{
            submitRequestAndValidateSuccessful("POST", fapiValidationFilter);
            submitRequestAndValidateSuccessful("PUT", fapiValidationFilter);
        }

        @Test
        void getAndDeleteRequestsAreNotValidated() throws Exception {
            final String httpMethod = "POST";
            final AttributesContext context = new AttributesContext(null);
            final Request request = new Request().setMethod(httpMethod);

            // Do a POST first, verify that it fails
            assertEquals(Status.BAD_REQUEST, fapiValidationFilter.filter(context, request, successHandler)
                                                                 .get(1, TimeUnit.SECONDS)
                                                                 .getStatus());

            // Submit the same invalid request but use HTTP methods which should be skipped
            final String[] skippedHttpMethods = {"GET, DELETE"};
            for (String method : skippedHttpMethods) {
                request.setMethod(method);
                // Verify we hit the SUCCESS_HANDLER
                assertEquals(Status.OK, fapiValidationFilter.filter(context, request, successHandler)
                                                            .get(1, TimeUnit.SECONDS)
                                                            .getStatus());
            }
        }

        @Test
        void failsWithRuntimeExceptionIfRegistrationRequestObjectNotFound() {
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(TEST_CERT_PEM, StandardCharsets.UTF_8)));

            // No registrationRequest in context
            final Context context = new AttributesContext(new RootContext());

            final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class,
                    () -> fapiValidationFilter.filter(context, request, successHandler));
            assertThat(illegalStateException).hasMessageContaining("Required attribute: \"registrationRequest\" not found in context");
        }

        @Test
        void invalidRequestFailsFieldLevelValidation() throws Exception {
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(TEST_CERT_PEM, StandardCharsets.UTF_8)));

            final Map<String, Object> invalidRegistrationRequest = new HashMap<>(VALID_REG_REQUEST_CLAIMS);
            invalidRegistrationRequest.put("token_endpoint_auth_method", "blah"); // invalidate one of the fields
            final Context context = createContext(createRegistrationRequest(invalidRegistrationRequest));

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA,
                    "token_endpoint_auth_method not supported, must be one of: " +
                            "[private_key_jwt, self_signed_tls_client_auth, tls_client_auth]");
        }

        @Test
        void invalidRequestMissingCert() throws Exception {
            final Request request = new Request().setMethod("POST");

            final Context context = createContext(VALID_REG_REQUEST);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
        }

        @Test
        void invalidRequestMalformedCert() throws Exception {
            final Request request = new Request().setMethod("POST");
            // %-1 is an invalid URL escape code
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, "%-1this is not URL encoded properly"));

            final Context context = createContext(VALID_REG_REQUEST);
            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
        }

        @Test
        void invalidRequestInvalidCert() throws Exception {
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode("this is an invalid cert......", StandardCharsets.UTF_8)));

            final Context context = createContext(VALID_REG_REQUEST);
            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
        }

        @Test
        void invalidRequestExpiredCert() throws Exception {
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(
                    convertToPem(generateExpiredX509Cert(generateRsaKeyPair(), "CN=test")), Charset.defaultCharset())));

            final Context context = createContext(VALID_REG_REQUEST);
            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA,
                    "MTLS client certificate has expired or cannot be used yet");
        }

        @Test
        void verifyUnexpectedRuntimeExceptionIsThrownOnByFilter() {
            // Trigger a runtime exception in one of the validators, verify that the exception is thrown on
            final IllegalStateException expectedException = new IllegalStateException("this should not have happened");
            final Validator<RegistrationRequest> brokenValidator = req -> {
                throw expectedException;
            };
            fapiValidationFilter.setRegistrationRequestObjectValidators(List.of(brokenValidator));

            final IllegalStateException actualException = assertThrows(IllegalStateException.class,
                    () -> submitRequestAndValidateSuccessful("POST", fapiValidationFilter));
            assertSame(expectedException, actualException);
        }
    }

    /**
     * Tests for the Heaplet configuration
     */
    @Nested
    class HeapletConfigurationTests {
        @Test
        void missingClientTlsCertHeaderMandatoryConfig() {
            final JsonValue filterConfig = json(object());
            final JsonValueException exception = assertThrows(JsonValueException.class,
                    () -> new Heaplet().create(Name.of("fapiTest"), filterConfig, EMPTY_HEAP));
            assertEquals("/clientTlsCertHeader: Expecting a value", exception.getMessage());
        }

        @Test
        void supportedSigningAlgorithmsConfigNotSupportedByFapiSpec() {
            final JsonValue filterConfig = json(object(field("supportedSigningAlgorithms", array("PS256", "RS256"))));
            final HeapException exception = assertThrows(HeapException.class,
                    () -> new Heaplet().create(Name.of("fapiTest"), filterConfig, EMPTY_HEAP));
            assertEquals("supportedSigningAlgorithms config must be the same as (or a subset of): [PS256, ES256]",
                    exception.getMessage());
        }

        @Test
        void supportedSupportedTokenEndpointAuthMethodsConfigNotSupportedByFapiSpec() {
            final JsonValue filterConfig = json(object(field("supportedTokenEndpointAuthMethods", array("private_key_jwt", "client_secret_basic"))));
            final HeapException exception = assertThrows(HeapException.class,
                    () -> new Heaplet().create(Name.of("fapiTest"), filterConfig, EMPTY_HEAP));
            assertEquals("supportedTokenEndpointAuthMethods config must be the same as (or a subset of): [tls_client_auth, self_signed_tls_client_auth, private_key_jwt]",
                    exception.getMessage());
        }

        @Test
        void createFilterWithDeprecatedClientTlsCertHeaderConfig() throws Exception {
            // Config which sets all the options, restricting the signing and auth methods to a single one each and extending the signing field names
            final JsonValue filterConfig = json(object(field("supportedTokenEndpointAuthMethods", array("private_key_jwt")),
                                                       field("supportedSigningAlgorithms", array("PS256")),
                                                       field("clientTlsCertHeader", CERT_HEADER_NAME),
                                                       field("registrationObjectSigningFieldNames",
                                                               array("token_endpoint_auth_signing_alg",
                                                                     "id_token_signed_response_alg",
                                                                     "request_object_signing_alg",
                                                                     "additional_signing_field_to_validate"))));

            final FapiAdvancedDCRValidationFilter filter = (FapiAdvancedDCRValidationFilter) new Heaplet().create(Name.of("fapiTest"), filterConfig, EMPTY_HEAP);

            final Map<String, Object> validRegRequestObj = new HashMap<>(VALID_REG_REQUEST_CLAIMS);
            validRegRequestObj.put("additional_signing_field_to_validate", "PS256"); // Add a value for the extra signing field that was configured via conf
            submitRequestAndValidateSuccessful("POST", filter);
        }

        @Test
        void createFilterWithCertificateRetrieverConfig() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("test"));
            final HeaderCertificateRetriever certificateRetriever = new HeaderCertificateRetriever(CERT_HEADER_NAME);
            heap.put("headerCertificateRetriever", certificateRetriever);

            // Config which sets all the options, restricting the signing and auth methods to a single one each and extending the signing field names
            final JsonValue filterConfig = json(object(field("supportedTokenEndpointAuthMethods", array("private_key_jwt")),
                    field("supportedSigningAlgorithms", array("PS256")),
                    field("certificateRetriever", "headerCertificateRetriever"),
                    field("registrationObjectSigningFieldNames",
                            array("token_endpoint_auth_signing_alg",
                                    "id_token_signed_response_alg",
                                    "request_object_signing_alg",
                                    "additional_signing_field_to_validate"))));

            final FapiAdvancedDCRValidationFilter filter = (FapiAdvancedDCRValidationFilter) new Heaplet().create(Name.of("fapiTest"), filterConfig, heap);

            final Map<String, Object> validRegRequestObj = new HashMap<>(VALID_REG_REQUEST_CLAIMS);
            validRegRequestObj.put("additional_signing_field_to_validate", "PS256"); // Add a value for the extra signing field that was configured via conf
            submitRequestAndValidateSuccessful("POST", filter);
        }
    }
}