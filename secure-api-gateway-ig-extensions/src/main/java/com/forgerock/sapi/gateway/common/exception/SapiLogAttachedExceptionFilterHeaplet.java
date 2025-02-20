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
package com.forgerock.sapi.gateway.common.exception;

import org.forgerock.openig.filter.LogAttachedExceptionFilter;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;

/**
 * Heaplet which creates a {@link LogAttachedExceptionFilter}
 *
 * For Secure API Gateway we are aliasing this filter as SapiLogAttachedExceptionFilter. We want to control where
 * the filter gets installed in a filter chain.
 *
 * The default installation in the Router causes us to have output which includes an invalid transactionId due to it
 * being before the filter that sets the transactionId for Secure API Gateway.
 *
 * The default installation still remains and this will handle any exceptions that are raised in between the 2 filters.
 */
public class SapiLogAttachedExceptionFilterHeaplet extends GenericHeaplet {
    @Override
    public Object create() throws HeapException {
        return new LogAttachedExceptionFilter();
    }

    @Override
    protected String getType() {
        return "SapiLogAttachedExceptionFilter";
    }
}
