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
package com.forgerock.sapi.gateway.dcr.request;


import java.io.IOException;
import java.util.function.BiFunction;

import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.Context;

/**
 * Supplies the Registration Request json object from a JWT contained within the Request.entity
 * <p>
 * The JWT signing algo in the header is validated against the supported set of signing algorithms for FAPI.
 * No other validation is done at this point, it is assumed that Filters later in the chain will validate the
 * sig etc
 */
public class RegistrationRequestEntitySupplier implements BiFunction<Context, Request, String> {

    public RegistrationRequestEntitySupplier() {
    }

    @Override
    public String apply(Context context, Request request)  {
        try {
            return request.getEntity().getString();
        } catch (IOException e) {
            // These are not validation errors, so do not raise a validation exception, instead allow the filter
            // to handle the null response
            return null;
        }
    }
}