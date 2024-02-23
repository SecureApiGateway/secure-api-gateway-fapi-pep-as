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
import java.util.SortedMap;
import java.util.TreeMap;

import org.forgerock.http.util.MultiValueMap;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Can be used to determine the most appropriate media type for the Entity in a response
 */
public class ContentTypeNegotiator {
    private final Logger logger = LoggerFactory.getLogger(ContentTypeNegotiator.class);
    private final List<String> supportedContentTypes;

    public ContentTypeNegotiator(List<String> supportedContentTypes) {
        Reject.ifNull(supportedContentTypes, "supportedContentTypes must not be null");
        if(supportedContentTypes.isEmpty()){
            throw new IllegalArgumentException("supportedContentTypes must not be empty");
        }
        this.supportedContentTypes = supportedContentTypes;
    }

    /**
     * Process the accepts header against a list of media types supported for the response
     * returns a string representing the supported media type that best meets the media 
     * types accepted by the client
     */
    public String getBestContentType(List<String> acceptHeaderValues) {
        if(acceptHeaderValues == null){
            acceptHeaderValues = List.of();
        }
        logger.debug("accept header contains {}", acceptHeaderValues);
        TreeMap<Float, List<String>> mediaTypesMap = buildMapOfAcceptableMediaTypes(acceptHeaderValues);
        String bestContentType = findHighestWeightedSupportedMediaType(mediaTypesMap);
        logger.debug("Best Content Type is {}", bestContentType);
        return bestContentType;
    }

    private TreeMap<Float, List<String>> buildMapOfAcceptableMediaTypes(List<String> acceptHeaderValues) {
        final TreeMap<Float, List<String>> mediaTypesMap = new TreeMap<>();
        MultiValueMap<Float, String> multiMediaTypesMap = new MultiValueMap<>(mediaTypesMap);
        for (String acceptValue : acceptHeaderValues) {
            String[] contentTypes = acceptValue.split(",");
            for (String contentType : contentTypes) {
                String[] contentTypeAndQ = contentType.split(";");
                if (contentTypeAndQ.length == 1) {
                    float defaultWeight = 1.0f;
                    multiMediaTypesMap.add( defaultWeight , contentTypeAndQ[0].trim().toLowerCase());
                } else if (contentTypeAndQ.length == 2){
                    String qValueStr = contentTypeAndQ[1].replace("q=", "");
                    float qValue = Float.parseFloat(qValueStr);
                    multiMediaTypesMap.add(qValue, contentTypeAndQ[0].trim().toLowerCase());
                } else {
                    logger.debug("Invalid content type entry found in Accept header {}", acceptHeaderValues);
                }
            }
        }
        return mediaTypesMap;
    }

    private String findHighestWeightedSupportedMediaType(TreeMap<Float, List<String>> mediaTypesMap) {
       SortedMap<Float, List<String>> reverseSortedContentTypes = mediaTypesMap.descendingMap();
       for(Float key: reverseSortedContentTypes.keySet()){
           List<String> values = reverseSortedContentTypes.get(key);
           logger.debug("{} weighting is {}", values, key);
           for(String value : values){
               String regexValue = value.replace("*", ".*");
               regexValue = regexValue.replace("/", "\\/");
               for(String supportedType : supportedContentTypes){
                   logger.trace("Checking if accepted media type '{}' matches supported type '{}'",
                           regexValue, supportedType);
                   if(supportedType.matches(regexValue)){
                       return supportedType;
                   }
               }
           }
       }
        logger.debug("No matching media types");
        return supportedContentTypes.get(0);
    }
}
