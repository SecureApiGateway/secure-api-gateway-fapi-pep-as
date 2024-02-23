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

import java.net.URISyntaxException;
import java.util.function.Function;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

public class ParResponseFetchApiClientFilterTest extends BaseAuthorizeResponseFetchApiClientFilterTest {

    @Override
    protected Function<Request, Promise<String, NeverThrowsException>> createClientIdRetriever() {
        return AuthorizeResponseFetchApiClientFilter.formClientIdRetriever();
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
        form.putSingle("client_id", clientId);
        request.setEntity(form);
        return request;
    }
}
