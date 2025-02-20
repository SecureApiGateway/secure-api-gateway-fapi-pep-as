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
package com.forgerock.sapi.gateway.common.jwt;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.ivy.util.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.util.Reject;

/**
 * Wrapper for accessing client provided Jwt claims. The JwtClaimSet class throws {@code RuntimeException}s when claims
 * can't be cast to the expected type, returns null when the claim does not exist, etc. This means there needs to be
 * significant error handling every time we access a claim. We need to handle all these conditions because the jwts have
 * been provided by the client and we can't guarantee what is in there and must at least end up with decent log entries
 * that explain the error, correlated with a transaction Id, and perhaps (optionally) an error_description field in
 * the 400 response body returned to the API client.
 * <p>
 * This wrapper class provides a base set of accessor methods that catch runtime exceptions and throw checked exceptions.
 * Using this class will force client code to handle those exceptions and ensure that a decent error message will
 * ultimately be provided to the client.
 */
public class ClaimsSetFacade {
    private final JwtClaimsSet claimsSet;

    public ClaimsSetFacade(JwtClaimsSet claimsSet) {
        Reject.ifNull(claimsSet, "claimSet must not be null");
        this.claimsSet = claimsSet;
    }

    public boolean hasExpired() throws JwtException {
        boolean hasExpired = false;
        Date expirationTime = claimsSet.getExpirationTime();
        if(expirationTime == null){
            throw new JwtException("JWT has no expiration date");
        }
        if (expirationTime.before(new Date())) {
            hasExpired = true;
        }
        return hasExpired;
    }

    public boolean hasClaim(String claimName) {
        return claimsSet.getClaim(claimName) != null;
    }

    /**
     * Get a String type claim from the JWT
     *
     * @param claimName the name of the claim
     * @return a valid (i.e. not null or empty) {@code String} containing the value associated with the claim
     * @throws JwtException if either the claim does not exist or it's value is either empty or not a String value
     */
    public String getStringClaim(String claimName) throws JwtException {
        checkClaimName(claimName);
        try {
            String claimValue = this.claimsSet.getClaim(claimName, String.class);
            if (StringUtils.isNullOrEmpty(claimValue)) {
                throw new JwtException("Jwt claim '" + claimName + "' must be valid string value");
            }
            return claimValue;
        } catch (ClassCastException exception) {
            throw new JwtException("Jwt must contain String claim '" + claimName + "'");
        }
    }

    /**
     * Get a String type claim from the JWT
     *
     * @param claimName the name of the claim
     * @return a valid (i.e. not null or empty) {@code String} containing the value associated with the claim
     * @throws JwtException if either the claim does not exist or it's value is either empty or not a String value
     */
    public List<String> getRequiredStringListClaim(String claimName) throws JwtException {
        Optional<List<String>> values = getOptionalStringListClaim(claimName);
        return values.orElseThrow(()->{ return new JwtException("Jwt claim '" + claimName + "' not defined");});
    }

    /**
     * Get a String type claim from the JWT
     *
     * @param claimName the name of the claim
     * @return a valid (i.e. not null or empty) {@code String} containing the value associated with the claim
     * @throws JwtException if either the claim does not exist or it's value is either empty or not a String value
     */
    public Optional<List<String>> getOptionalStringListClaim(String claimName) throws JwtException {
        checkClaimName(claimName);
        try {
            JsonValue claimValue = this.claimsSet.get(claimName);
            if (claimValue.getObject() == null) {
                return Optional.empty();
            }
            if (claimValue.isList()){
                List<Object> valuesAsList = claimValue.asList();
                List<String> valuesAsStringList = valuesAsList.stream().map(String.class::cast).collect(Collectors.toList());
                return Optional.of(valuesAsStringList);
            } else {
                throw new JwtException("Jwt claim '" + claimName + "' is not of type List");
            }
        } catch (ClassCastException exception) {
            throw new JwtException("Jwt claim '" + claimName + "' is not a List of Strings");
        }
    }

    public List<URI> getRequiredUriListClaim(String claimName) throws JwtException {
        checkClaimName(claimName);
        try {
            JsonValue claimValue = this.claimsSet.get(claimName);
            if (claimValue.getObject() == null) {
                throw new JwtException("claim of name " + claimName + " must exist in the JWT");
            }
            if (claimValue.isList()){
                List<Object> claimValueList = claimValue.asList();
                List<URI> uriList = new ArrayList<>(claimValueList.size());
                for(int index = 0; index < claimValueList.size(); index++){
                    Object claim = claimValueList.get(index);
                    try {
                        final URI uri = new URI((String)claim);
                        uriList.add(index, uri);
                    } catch (URISyntaxException e) {
                        throw new JwtException("claim of name '" + claimName + "' is expected to hold valid URIs: " + e.getMessage());
                    }
                }
                return uriList;
            } else {
                throw new JwtException("claim of name '" + claimName + "' is not of type List");
            }
        } catch (ClassCastException exception) {
            throw new JwtException("claim of name '" + claimName + "' is not a List of Strings");
        }
    }


    /**
     * Get the value of a string claim from the claims set and convert it to a URI
     *
     * @param claimName the name of the string claim that is expected to hold a valid URI
     * @return a {@code URI}
     * @throws JwtException if the claim does not exist, or holds an empty string, or is not a string, or if the value
     *                      of the string is not a valid URL
     */
    public URI getStringClaimAsURI(String claimName) throws JwtException {
        checkClaimName(claimName);
        try {
            String claimValueAsString = this.claimsSet.getClaim(claimName, String.class);
            if (StringUtils.isNullOrEmpty(claimValueAsString)) {
                throw new JwtException("Jwt claim '" + claimName + "' must be valid URI as a String value");
            }
            try {
                return new URI(claimValueAsString);
            } catch (URISyntaxException e) {
                throw new JwtException("Jwt claim '" + claimName + "' must be a valid URI as a String Value");
            }
        } catch (ClassCastException exception) {
            throw new JwtException("Jwt must contain URL claim '" + claimName + "'");
        }
    }

    /**
     * Get the value of a JsonValue claim from the claims set
     *
     * @param claimName the name of the claim
     * @return a JsonValue containing the value of the claim
     * @throws JwtException if the claim does not exist, is null or can't be represented as a JsonValue
     */
    public JsonValue getJsonValueClaim(String claimName) throws JwtException {
        checkClaimName(claimName);
        JsonValue claimValue = claimsSet.get(claimName);
        if (claimValue == null || claimValue.getObject() == null) {
            throw new JwtException("Jwt must have '" + claimName + "' claim");
        }
        return claimValue;
    }

    private void checkClaimName(String claimName) {
        if (StringUtils.isNullOrEmpty(claimName)) {
            throw new IllegalArgumentException("claimName must not be null or empty");
        }
    }

    public String getIssuer() throws JwtException {
        String issuer = claimsSet.getIssuer();
        if (StringUtils.isNullOrEmpty(issuer)) {
            throw new JwtException("Jwt must contain 'iss' claim");
        }
        return issuer;
    }

    public ClaimsSetFacade setStringArrayClaim(String claimName, List<String> values) {
        this.claimsSet.setClaim(claimName, values);
        return this;
    }

    public ClaimsSetFacade setClaim(String claimName, Object value){
        this.claimsSet.setClaim(claimName, value);
        return this;
    }

    public ClaimsSetFacade setStringClaim(String claimName, String value){
        this.claimsSet.setClaim(claimName, value);
        return this;
    }

    public String build(){
        return this.claimsSet.build();
    }
}
