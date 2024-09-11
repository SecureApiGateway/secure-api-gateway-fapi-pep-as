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
package com.forgerock.sapi.gateway.dcr.filter;

import static com.forgerock.sapi.gateway.dcr.filter.TokenEndpointResponseFetchApiClientFilter.DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.filter.TokenEndpointResponseFetchApiClientFilter.Heaplet;
import com.forgerock.sapi.gateway.dcr.service.ApiClientService;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilterTest;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

public class TokenEndpointResponseFetchApiClientFilterTest extends BaseResponsePathFetchApiClientFilterTest {

    @Override
    protected Filter createFilter() {
        final HeapImpl heap = new HeapImpl(Name.of("heap"));
        heap.put("apiClientService", apiClientService);
        final JsonValue config = json(object(field("apiClientService", "apiClientService")));
        try {
            return (Filter) new Heaplet().create(Name.of("test"), config, heap);
        } catch (HeapException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Request createRequest() {
        // Default request, this filter is only interested in response data.
        return new Request();
    }

    @Override
    protected Response createValidUpstreamResponse() {
        return ResponsePathTransportCertValidationFilterTest.createResponseWithAccessToken(CLIENT_ID);
    }

    @Test
    void returnsErrorResponseWhenClientIdParamNotFound() throws Exception {
        final Response response = new Response(Status.OK);
        returnsErrorResponseWhenClientIdParamNotFound(createRequest(), response);
    }


    @Test
    void testParseClientIdMissingAccessToken() {
        final TokenEndpointResponseFetchApiClientFilter filter = createFilterWithMockApiClient();

        final JsonValue jsonResponseMissingAccessTokenField = json(object(field("someOtherKey", "someOtherValue")));
        final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class, () -> filter.getClientIdFromJsonEntity(jsonResponseMissingAccessTokenField));
        assertEquals("Failed to get client_id: access_token is missing", illegalStateException.getMessage());
    }

    private static TokenEndpointResponseFetchApiClientFilter createFilterWithMockApiClient() {
        return new TokenEndpointResponseFetchApiClientFilter(
                mock(ApiClientService.class), DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM);
    }

    @Test
    void testParseClientIdAccessTokenNotJwt() {
        final TokenEndpointResponseFetchApiClientFilter filter = createFilterWithMockApiClient();

        final JsonValue accessTokenInvalidJwt = json(object(field("access_token", "sdfsfsdfsdfsf")));
        final InvalidJwtException invalidJwtException = assertThrows(InvalidJwtException.class, () -> filter.getClientIdFromJsonEntity(accessTokenInvalidJwt));
        assertEquals("not right number of dots, 1", invalidJwtException.getMessage());
    }

    @Test
    void testParseClientIdAccessTokenMissingClientIdClaim() {
        final TokenEndpointResponseFetchApiClientFilter filter = createFilterWithMockApiClient();

        final JsonValue accessTokenMissingClientIdClaim = json(object(field("access_token", createAccessToken(Map.of("claim1", "value1")))));
        final IllegalStateException illegalStateException = assertThrows(IllegalStateException.class, () -> filter.getClientIdFromJsonEntity(accessTokenMissingClientIdClaim));
        assertEquals("Failed to get client_id: access_token claims missing required '" + DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM + "' claim", illegalStateException.getMessage());
    }

    @Test
    void testParseClientIdSuccessfully() {
        final TokenEndpointResponseFetchApiClientFilter filter = createFilterWithMockApiClient();

        final String clientId = "clientId123";
        final JsonValue accessTokenClientIdNotString = json(object(field("access_token", createAccessToken(Map.of(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM, clientId)))));
        assertEquals(clientId, filter.getClientIdFromJsonEntity(accessTokenClientIdNotString));
    }

    private static String createAccessToken(Map<String, Object> claims) {
        return CryptoUtils.createEncodedJwtString(claims, JWSAlgorithm.PS256);
    }

}
