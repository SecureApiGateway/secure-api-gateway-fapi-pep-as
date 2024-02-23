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
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateExpiredX509Cert;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateRsaKeyPair;
import static com.forgerock.sapi.gateway.util.CryptoUtils.generateX509Cert;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.TransactionId;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.TransactionIdContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.common.exceptions.ValidationException;
import com.forgerock.sapi.gateway.dcr.common.Validator;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.fapi.v1.FAPIAdvancedDCRValidationFilter.Heaplet;
import com.forgerock.sapi.gateway.mtls.HeaderCertificateRetriever;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class FAPIAdvancedDCRValidationFilterTest {

    private static final String CERT_HEADER_NAME = "x-cert";

    private static final String TEST_CERT_PEM = convertToPem(generateX509Cert(generateRsaKeyPair(), "CN=fapitest"));

    private static RSASSASigner RSA_SIGNER;
    private static Map<String, Object> VALID_REG_REQUEST_OBJ;
    private static final HeapImpl EMPTY_HEAP = new HeapImpl(Name.of("testHeap"));

    private TestSuccessResponseHandler successHandler;

    private FAPIAdvancedDCRValidationFilter fapiValidationFilter;

    @BeforeAll
    public static void beforeAll() throws NoSuchAlgorithmException {
        RSA_SIGNER = createRSASSASigner();
        VALID_REG_REQUEST_OBJ = Map.of("token_endpoint_auth_method", "private_key_jwt",
                                       "scope", "openid accounts payments",
                                       "redirect_uris", List.of("https://google.co.uk"),
                                       "response_types", List.of("code id_token"),
                                       "token_endpoint_auth_signing_alg", "PS256",
                                       "id_token_signed_response_alg", "PS256",
                                       "request_object_signing_alg", "PS256");
    }

    @BeforeEach
    public void beforeEach() throws HeapException {
        fapiValidationFilter = createDefaultFapiFilter();
        successHandler = new TestSuccessResponseHandler();
    }

    /**
     * JWT signer which uses generated test RSA private key
     */
    private static RSASSASigner createRSASSASigner() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSASSASigner(pair.getPrivate());
    }

    /**
     * Uses the Heaplet to create a FAPIAdvancedDCRValidationFilter with the default configuration.
     */
    private static FAPIAdvancedDCRValidationFilter createDefaultFapiFilter() throws HeapException {
        final JsonValue filterConfig = json(object(field("clientTlsCertHeader", CERT_HEADER_NAME)));
        return (FAPIAdvancedDCRValidationFilter) new FAPIAdvancedDCRValidationFilter.Heaplet()
                                                                                    .create(Name.of("fapiTest"),
                                                                                            filterConfig, EMPTY_HEAP);
    }

    private String createSignedJwt(Map<String, Object> claims) {
        return createSignedJwt(claims, JWSAlgorithm.PS256);
    }

    private String createSignedJwt(Map<String, Object> claims, JWSAlgorithm signingAlgo) {
        try {
            final SignedJWT signedJWT = new SignedJWT(new JWSHeader(signingAlgo), JWTClaimsSet.parse(claims));
            signedJWT.sign(RSA_SIGNER);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
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

    private void submitRequestAndValidateSuccessful(String httpMethod, Map<String, Object> validRegRequestObj,
            String testCertPem, FAPIAdvancedDCRValidationFilter filter) throws Exception {
        final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
        final Request request = new Request().setMethod(httpMethod);
        request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(testCertPem, StandardCharsets.UTF_8)));

        final String signedJwt = createSignedJwt(validRegRequestObj);
        request.getEntity().setString(signedJwt);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, successHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        if (!response.getStatus().isSuccessful()) {
            fail("Expected a successful response instead got: " + response.getStatus() + ", entity: " + response.getEntity().getJson());
        }
        assertTrue(successHandler.hasBeenInteractedWith(), "Filter was expected to pass the request on to the successHandler");
    }

    /**
     * Tests for the individual validators which validate particular fields within the Registration Request JWT.
     */
    @Nested
    class RegistrationRequestObjectFieldValidatorTests {

        private <T> void runValidationAndVerifyExceptionThrown(Validator<T> validator, T requestObject,
                DCRErrorCode expectedErrorCode, String expectedErrorMessage) {
            final ValidationException validationException = Assertions.assertThrows(ValidationException.class,
                    () -> validator.validate(requestObject));
            assertEquals(expectedErrorCode, validationException.getErrorCode(), "errorCode field");
            assertEquals(expectedErrorMessage, validationException.getErrorDescription(), "errorMessage field");
        }


        @Test
        void redirectUrisFieldMissing() {
            final JsonValue missingField = json(object());
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, missingField,
                    DCRErrorCode.INVALID_REDIRECT_URI, "request object must contain redirect_uris field");
        }

        @Test
        void redirectUrisArrayEmpty() {
            final JsonValue emptyArray = json(object(field("redirect_uris", array())));
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, emptyArray,
                    DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris array must not be empty");
        }

        @Test
        void redirectUrisNonHttpsUri() {
            final JsonValue nonHttpsRedirect = json(object(field("redirect_uris",
                    array("https://www.google.com", "http://www.google.co.uk"))));
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, nonHttpsRedirect,
                    DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris must use https scheme");
        }

        @Test
        void redirectUrisMalformedUri() {
            final JsonValue nonHttpsRedirect = json(object(field("redirect_uris", array("https://www.google.com", "123:@///324dfs+w34r"))));
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateRedirectUris, nonHttpsRedirect,
                    DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uri: 123:@///324dfs+w34r is not a valid URI");
        }

        @Test
        void validRedirectUris() {
            final JsonValue validRedirect = json(object(field("redirect_uris", array("https://www.google.com", "https://www.google.co.uk"))));
            fapiValidationFilter.validateRedirectUris(validRedirect);
        }

        @Test
        void tokenEndpointAuthMethodFieldMissing() {
            final JsonValue missingField = json(object());
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateTokenEndpointAuthMethods, missingField,
                    DCRErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: token_endpoint_auth_method");
        }

        @Test
        void tokenEndpointAuthMethodValueNotSupported() {
            final String[] invalidAuthMethods = new String[]{"", "none", "client_secret"};
            for (String invalidAuthMethod : invalidAuthMethods) {
                final JsonValue invalidAuthMethodJson = json(object(field("token_endpoint_auth_method", invalidAuthMethod)));
                runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateTokenEndpointAuthMethods, invalidAuthMethodJson,
                        DCRErrorCode.INVALID_CLIENT_METADATA, "token_endpoint_auth_method not supported, must be one of: [private_key_jwt, self_signed_tls_client_auth, tls_client_auth]");
            }
        }

        @Test
        void tokenEndpointAuthMethodValid() {
            final String[] validMethods = new String[]{"private_key_jwt", "self_signed_tls_client_auth", "tls_client_auth"};
            for (String validAuthMethod : validMethods) {
                final JsonValue validAuthMethodJson = json(object(field("token_endpoint_auth_method", validAuthMethod)));
                fapiValidationFilter.validateTokenEndpointAuthMethods(validAuthMethodJson);
            }
        }

        @Test
        void signingAlgorithmFieldsMissingAreSkipped() {
            final List<String> signingAlgoFields = List.of("token_endpoint_auth_signing_alg", "id_token_signed_response_alg",
                                                           "request_object_signing_alg");

            // Test submitting requests which each omit one of the fields in turn
            for (String fieldToOmit : signingAlgoFields) {
                final JsonValue registrationRequest = json(object());
                signingAlgoFields.stream().filter(field -> !field.equals(fieldToOmit)).forEach(field -> registrationRequest.add(field, "PS256"));
                fapiValidationFilter.validateSigningAlgorithmUsed(registrationRequest);
            }
        }

        @Test
        void signingAlgorithmFieldsUnsupportedAlgo() {
            final List<String> signingAlgoFields = List.of("token_endpoint_auth_signing_alg", "id_token_signed_response_alg",
                    "request_object_signing_alg");

            // Test submitting requests which each set one of the fields to an invalid algorithm in turn
            for (String invalidAlgoField : signingAlgoFields) {
                final JsonValue registrationRequest = json(object());
                signingAlgoFields.stream().filter(field -> !field.equals(invalidAlgoField)).forEach(field -> registrationRequest.add(field, "PS256"));
                registrationRequest.add(invalidAlgoField, "RS256");
                runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateSigningAlgorithmUsed, registrationRequest,
                        DCRErrorCode.INVALID_CLIENT_METADATA, "request object field: " + invalidAlgoField + ", must be one of: [ES256, PS256]");
            }
        }

        @Test
        void signingAlgorithmFieldsValid() {
            fapiValidationFilter.validateSigningAlgorithmUsed(json(object(field("token_endpoint_auth_signing_alg", "PS256"),
                    field("id_token_signed_response_alg", "PS256"),
                    field("request_object_signing_alg", "PS256"))));
        }

        @Test
        void responseTypeFieldMissing() {
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, json(object(field("blah", "blah"))),
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
                fapiValidationFilter.validateResponseTypes(json(object(field("response_types", array(validResponseTypeValue.toArray())))));
            }
        }

        @Test
        void responseTypesInvalid() {
            runValidationAndVerifyExceptionThrown(fapiValidationFilter::validateResponseTypes, json(object(field("response_types", array("blah")))),
                    DCRErrorCode.INVALID_CLIENT_METADATA, "Invalid response_types value: blah, must be one of: \"code\" or \"code id_token\"");
        }
    }

    /**
     * Tests which invoke the Filter's filter method, passing HTTP Request and Context objects and validate the
     * HTTP Response is valid.
     */
    @Nested
    class FilterHttpRequestTests {

        @Test
        void validRequest() throws Exception{
            submitRequestAndValidateSuccessful("POST", VALID_REG_REQUEST_OBJ, TEST_CERT_PEM, fapiValidationFilter);
            submitRequestAndValidateSuccessful("PUT", VALID_REG_REQUEST_OBJ, TEST_CERT_PEM, fapiValidationFilter);
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
        void invalidRequestFailsFieldLevelValidation() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(TEST_CERT_PEM, StandardCharsets.UTF_8)));

            final Map<String, Object> invalidRegistrationRequest = new HashMap<>(VALID_REG_REQUEST_OBJ);
            invalidRegistrationRequest.put("token_endpoint_auth_method", "blah"); // invalidate one of the fields
            final String signedJwt = createSignedJwt(invalidRegistrationRequest);
            request.getEntity().setString(signedJwt);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA,
                    "token_endpoint_auth_method not supported, must be one of: " +
                            "[private_key_jwt, self_signed_tls_client_auth, tls_client_auth]");
        }

        @Test
        void invalidRequestMissingCert() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");

            final Map<String, Object> validRegRequestObj = VALID_REG_REQUEST_OBJ;
            final String signedJwt = createSignedJwt(validRegRequestObj);
            request.getEntity().setString(signedJwt);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
        }

        @Test
        void invalidRequestMalformedCert() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");
            // %-1 is an invalid URL escape code
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, "%-1this is not URL encoded properly"));

            final Map<String, Object> validRegRequestObj = VALID_REG_REQUEST_OBJ;
            final String signedJwt = createSignedJwt(validRegRequestObj);
            request.getEntity().setString(signedJwt);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
        }

        @Test
        void invalidRequestInvalidCert() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode("this is an invalid cert......", StandardCharsets.UTF_8)));

            final Map<String, Object> validRegRequestObj = VALID_REG_REQUEST_OBJ;
            final String signedJwt = createSignedJwt(validRegRequestObj);
            request.getEntity().setString(signedJwt);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
        }

        @Test
        void invalidRequestExpiredCert() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(
                    convertToPem(generateExpiredX509Cert(generateRsaKeyPair(), "CN=test")), Charset.defaultCharset())));

            final Map<String, Object> validRegRequestObj = VALID_REG_REQUEST_OBJ;
            final String signedJwt = createSignedJwt(validRegRequestObj);
            request.getEntity().setString(signedJwt);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA,
                    "MTLS client certificate has expired or cannot be used yet");
        }

        @Test
        void invalidRequestInvalidJwt() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(TEST_CERT_PEM, StandardCharsets.UTF_8)));
            request.getEntity().setString("plain text instead of a JWT");

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "registration request entity is missing or malformed");
        }

        @Test
        void invalidRequestJwtSignedWithUnsupportedAlgo() throws Exception {
            final TransactionIdContext context = new TransactionIdContext(null, new TransactionId("1234"));
            final Request request = new Request().setMethod("POST");
            request.addHeaders(new GenericHeader(CERT_HEADER_NAME, URLEncoder.encode(TEST_CERT_PEM, StandardCharsets.UTF_8)));

            // RS256 JWT signing algorithm not supported
            final String signedJwt = createSignedJwt(VALID_REG_REQUEST_OBJ, JWSAlgorithm.RS256);
            request.getEntity().setString(signedJwt);

            final Promise<Response, NeverThrowsException> responsePromise = fapiValidationFilter.filter(context, request, successHandler);

            final Response response = responsePromise.get(1, TimeUnit.SECONDS);
            Assertions.assertFalse(response.getStatus().isSuccessful(), "Request must fail");
            validateErrorResponse(response, DCRErrorCode.INVALID_CLIENT_METADATA, "DCR request JWT signed must be signed with one of: [ES256, PS256]");
        }

        @Test
        void verifyUnexpectedRuntimeExceptionIsThrownOnByFilter() {
            // Trigger a runtime exception in one of the validators, verify that the exception is thrown on
            final IllegalStateException expectedException = new IllegalStateException("this should not have happened");
            final Validator<JsonValue> brokenValidator = req -> {
                throw expectedException;
            };
            fapiValidationFilter.setRegistrationRequestObjectValidators(List.of(brokenValidator));

            final IllegalStateException actualException = assertThrows(IllegalStateException.class,
                    () -> submitRequestAndValidateSuccessful("POST", VALID_REG_REQUEST_OBJ, TEST_CERT_PEM, fapiValidationFilter));
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

            final FAPIAdvancedDCRValidationFilter filter = (FAPIAdvancedDCRValidationFilter) new Heaplet().create(Name.of("fapiTest"), filterConfig, EMPTY_HEAP);

            final Map<String, Object> validRegRequestObj = new HashMap<>(VALID_REG_REQUEST_OBJ);
            validRegRequestObj.put("additional_signing_field_to_validate", "PS256"); // Add a value for the extra signing field that was configured via conf
            submitRequestAndValidateSuccessful("POST", validRegRequestObj, TEST_CERT_PEM, filter);
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

            final FAPIAdvancedDCRValidationFilter filter = (FAPIAdvancedDCRValidationFilter) new Heaplet().create(Name.of("fapiTest"), filterConfig, heap);

            final Map<String, Object> validRegRequestObj = new HashMap<>(VALID_REG_REQUEST_OBJ);
            validRegRequestObj.put("additional_signing_field_to_validate", "PS256"); // Add a value for the extra signing field that was configured via conf
            submitRequestAndValidateSuccessful("POST", validRegRequestObj, TEST_CERT_PEM, filter);
        }
    }
}