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
package com.forgerock.sapi.gateway.jwt;

import static java.util.Objects.requireNonNull;

import org.forgerock.json.jose.jwt.Payload;
import org.forgerock.json.jose.utils.Utils;

/**
 * Class representing an octet-sequence-based {@link Payload}, which is managed as an immutable {@link String}.
 */
public class OctetSequencePayload implements Payload {

    private String payload;

    /**
     * Construct an {@code OctetSequencePayload}.
     * @param octetSequence octetSequence payload
     */
    public OctetSequencePayload(final byte[] octetSequence) {
        this.payload = new String(requireNonNull(octetSequence), Utils.CHARSET);
    }

    private OctetSequencePayload(final OctetSequencePayload other) {
        this.payload = other.payload;
    }

    @Override
    public String build() {
        return payload;
    }

    @Override
    public OctetSequencePayload copy() {
        return new OctetSequencePayload(this);
    }
}
