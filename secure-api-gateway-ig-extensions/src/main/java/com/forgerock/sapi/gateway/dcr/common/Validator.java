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
package com.forgerock.sapi.gateway.dcr.common;

import com.forgerock.sapi.gateway.dcr.common.exceptions.ValidationException;

/**
 * Validator used to validate objects as part of Dynamic Client Registration.
 *
 * @param <T> the type of the object which can be validated
 */
@FunctionalInterface
public interface Validator<T> {

    /**
     * Method which applies validation rules to an object.
     * <p>
     * If validation passes then the method will return as normal, if validation fails then a ValidationException
     * must be thrown.
     *
     * @param t the object to validate
     * @throws ValidationException must be thrown if validation fails
     */
    void validate(T t) throws ValidationException;

}
