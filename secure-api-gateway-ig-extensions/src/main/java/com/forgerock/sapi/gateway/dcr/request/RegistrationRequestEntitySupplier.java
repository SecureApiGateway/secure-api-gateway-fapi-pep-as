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
package com.forgerock.sapi.gateway.dcr.request;


import java.io.IOException;
import java.util.function.BiFunction;

import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * Supplies the Registration Request json object from a JWT contained within the Request.entity
 */
public class RegistrationRequestEntitySupplier implements BiFunction<Context, Request, Promise<String, IOException>> {

    public RegistrationRequestEntitySupplier() {
    }

    @Override
    public Promise<String, IOException> apply(Context context, Request request)  {
        return request.getEntity().getStringAsync();
    }
}