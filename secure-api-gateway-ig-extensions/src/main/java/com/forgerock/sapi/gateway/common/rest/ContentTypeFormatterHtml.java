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

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Formats a map of String key value pairs into a representative HTML string
 */
public class ContentTypeFormatterHtml implements ContentTypeFormatter{
    private static final Logger logger = LoggerFactory.getLogger(ContentTypeFormatterHtml.class);

    public String getFormattedResponse(Map<String, String> errorForm) {
        if(errorForm == null){
            errorForm = Map.of();
        }
        StringBuilder errorMessageBuilder = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta " +
                "charset=\"utf-8\"><title>" + "Error Response" +
                "</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>");
        errorForm.forEach((key, val) -> {
            logger.debug("processing entry for {}, val is {}", key, val);
            errorMessageBuilder.append("<p><b>")
                    .append(key)
                    .append(":</b> ")
                    .append(val)
                    .append("</p>");
        });
        errorMessageBuilder.append("</body></html>");
        String htmlErrorMessage = errorMessageBuilder.toString();
        logger.debug("html error message is {}", htmlErrorMessage);
        return htmlErrorMessage;
    }
}
