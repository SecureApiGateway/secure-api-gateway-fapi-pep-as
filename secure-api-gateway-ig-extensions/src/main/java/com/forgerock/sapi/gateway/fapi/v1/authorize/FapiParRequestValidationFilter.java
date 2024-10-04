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
package com.forgerock.sapi.gateway.fapi.v1.authorize;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * Validates that a request made to the OAuth2.0 /par (Pushed Authorization Request) endpoint is FAPI compliant.
 * <p>
 * For /par requests, the request JWT is supplied as an HTTP Form parameter.
 * <p>
 * For more details see:
 * <a href="https://datatracker.ietf.org/doc/html/rfc9126#name-pushed-authorization-reques">OAuth 2.0 Pushed Authorization Requests</a>
 */
public class FapiParRequestValidationFilter extends BaseFapiAuthorizeRequestValidationFilter {

    /**
     * Retrieves parameters from the HTTP Request's Form
     *
     * @param request   Request the HTTP Request to retrieve the parameter from
     * @param paramName String the name of the parameter
     * @return Promise<String, NeverThrowsException> a promise containing the String value of the parameter or null if
     * the parameter does not exist or if an exception is thrown.
     */
    @Override
    protected Promise<String, NeverThrowsException> getParamFromRequest(Request request, String paramName) {
        return request.getEntity().getFormAsync()
                .then(form -> form.getFirst(paramName))
                .thenCatch(ioe -> {
                    logger.warn("Failed to extract data from /par request due to exception", ioe);
                    return null;
                });
    }

    @Override
    protected Promise<List<String>, NeverThrowsException> removeNonMatchingParamsFromRequest(Request request,
            List<String> paramNamesToKeep) {
        try {
            final Form form =  request.getEntity().getForm();
            List<String> paramsToRemove = new ArrayList<>();
            form.keySet().forEach((formParamKey)-> {
                if (!paramNamesToKeep.contains(formParamKey)) {
                    paramsToRemove.add(formParamKey);
                }
            });

            paramsToRemove.forEach((paramToRemove)->{
                List<String> result = form.remove(paramToRemove);
                if(result != null){
                    logger.debug("Removed form parameter '{}' from PAR request", paramToRemove);
                }
            });
            request.setEntity(form);
            return Promises.newResultPromise(paramsToRemove);
        } catch (IOException e) {
            logger.warn("Failed to remove param from /par request form due to exception", e);
            return Promises.newResultPromise(List.of());
        }
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FapiParRequestValidationFilter();
        }
    }
}
