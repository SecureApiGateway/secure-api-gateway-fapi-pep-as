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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

public class ParResponseFetchApiClientFilterTest extends BaseResponsePathFetchApiClientFilterTest {

    @Override
    protected ResponsePathFetchApiClientFilter createFilter() {
        final HeapImpl heap = new HeapImpl(Name.of("heap"));
        heap.put("apiClientService", apiClientService);
        final JsonValue config = json(object(field("apiClientService", "apiClientService")));
        try {
            return (ResponsePathFetchApiClientFilter) new ParResponseFetchApiClientFilterHeaplet().create(Name.of("test"), config, heap);
        } catch (HeapException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Request createRequest() {
        final Request request = new Request();
        request.setMethod("POST");
        try {
            request.setUri("https://localhost/am/par");
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        final Form form = new Form();
        form.putSingle("request", CryptoUtils.createEncodedJwtString(Map.of("client_id", CLIENT_ID), JWSAlgorithm.PS256));
        request.setEntity(form);
        return request;
    }

    @Override
    protected Response createValidUpstreamResponse() {
        return new Response(Status.OK);
    }

    @Test
    void returnsErrorResponseWhenClientIdParamNotFound() throws Exception {
        returnsErrorResponseWhenClientIdParamNotFound(new Request().setUri("/authorize"), createValidUpstreamResponse());
    }

    @Test
    public void failsToRetreiveClientIdWhenRequestJwtIsMissing() throws Exception {
        Request request = new Request();
        request.setEntity(new Form());
        final Promise<String, NeverThrowsException> clientIdPromise =
                ParResponseFetchApiClientFilterHeaplet.formRequestJwtClientIdRetriever().apply(request);

        final String clientId = clientIdPromise.getOrThrow(1, TimeUnit.MILLISECONDS);
        assertThat(clientId).isNull();
    }

    @Test
    public void failsToRetrieveClientIdWhenRequestJwtIsInvalid() throws Exception {
        Request request = new Request();
        final Form form = new Form();
        form.putSingle("request", "this is not a jwt");
        request.setEntity(form);
        final Promise<String, NeverThrowsException> clientIdPromise =
                ParResponseFetchApiClientFilterHeaplet.formRequestJwtClientIdRetriever().apply(request);

        final String clientId = clientIdPromise.getOrThrow(1, TimeUnit.MILLISECONDS);
        assertThat(clientId).isNull();
    }

    @Test
    public void failsToRetrieveClientIdWhenRequestJwtDoesNotIncludeClientIdClaim() throws Exception {
        Request request = new Request();
        final Form form = new Form();
        form.putSingle("request", CryptoUtils.createEncodedJwtString(Map.of("claim1", "value1"), JWSAlgorithm.PS256));
        request.setEntity(form);
        final Promise<String, NeverThrowsException> clientIdPromise =
                ParResponseFetchApiClientFilterHeaplet.formRequestJwtClientIdRetriever().apply(request);

        final String clientId = clientIdPromise.getOrThrow(1, TimeUnit.MILLISECONDS);
        assertThat(clientId).isNull();
    }
}
