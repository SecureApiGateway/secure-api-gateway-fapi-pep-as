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
package com.forgerock.sapi.gateway.common.rest;

import java.util.List;

/**
 * Used to obtain a {@code ContentTypeFormatter} for an {@code HttpMediaType}
 */
public class ContentTypeFormatterFactory {

    private final List<String> supportedContentTypes;

    public ContentTypeFormatterFactory() {
        supportedContentTypes = List.of(HttpMediaTypes.APPLICATION_JSON, HttpMediaTypes.TEXT_HTML,
                HttpMediaTypes.APPLICATION_TEXT);

    }

    /**
     * Specifies the content types supported by the formatting factory
     * @return a list of Strings that match the values in {@code HttpMediaTypes} that specify what formatters are
     * available
     */
    public List<String> getSupportedContentTypes() {
        return supportedContentTypes;
    }

    /**
     * Return a formatter for the provided media type
     * @param mediaType the media type as defined in {@code HttpMediaTypes} for which a formatter is required
     * @return a formatter that can be used to produce a string containing the media type requested
     */
    public ContentTypeFormatter getFormatter(String mediaType) {
        switch(mediaType){
        case HttpMediaTypes.TEXT_HTML:
            return new ContentTypeFormatterHtml();
        case HttpMediaTypes.APPLICATION_TEXT:
            return new ContentTypeFormatterText();
        case HttpMediaTypes.APPLICATION_JSON:
        default:
            return new ContentTypeFormatterJson();
        }
    }

}
