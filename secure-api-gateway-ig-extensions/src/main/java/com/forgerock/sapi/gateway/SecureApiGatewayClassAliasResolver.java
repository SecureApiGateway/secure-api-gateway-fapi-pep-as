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
package com.forgerock.sapi.gateway;

import java.util.HashMap;
import java.util.Map;

import org.forgerock.openig.alias.ClassAliasResolver;

import com.forgerock.sapi.gateway.am.AccessTokenResponseIdTokenReSignFilter;
import com.forgerock.sapi.gateway.am.AuthorizeResponseJwtReSignFilter;
import com.forgerock.sapi.gateway.am.JwtReSigner;
import com.forgerock.sapi.gateway.common.exception.SapiLogAttachedExceptionFilterHeaplet;
import com.forgerock.sapi.gateway.consent.ConsentRequestAccessAuthorisationFilter;
import com.forgerock.sapi.gateway.dcr.filter.AuthorizeResponseFetchApiClientFilterHeaplet;
import com.forgerock.sapi.gateway.dcr.filter.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter;
import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter.PathParamClientIdRequestParameterLocator;
import com.forgerock.sapi.gateway.dcr.filter.ManageApiClientFilter.QueryParamClientIdRequestParameterLocator;
import com.forgerock.sapi.gateway.dcr.filter.ParResponseFetchApiClientFilterHeaplet;
import com.forgerock.sapi.gateway.dcr.filter.TokenEndpointResponseFetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.request.RegistrationRequestBuilderFilter;
import com.forgerock.sapi.gateway.fapi.FapiInteractionIdTracingFilter;
import com.forgerock.sapi.gateway.fapi.v1.FapiAdvancedDCRValidationFilter;
import com.forgerock.sapi.gateway.fapi.v1.authorize.FapiAuthorizeRequestValidationFilter;
import com.forgerock.sapi.gateway.fapi.v1.authorize.FapiParRequestValidationFilter;
import com.forgerock.sapi.gateway.jws.RsaJwtSignatureValidator;
import com.forgerock.sapi.gateway.jws.signer.CompactSerializationJwsSigner;
import com.forgerock.sapi.gateway.metrics.RouteMetricsFilter;
import com.forgerock.sapi.gateway.metrics.TokenEndpointMetricsContextSupplier;
import com.forgerock.sapi.gateway.mtls.AddCertificateToAttributesContextFilter;
import com.forgerock.sapi.gateway.mtls.ContextCertificateRetriever;
import com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator;
import com.forgerock.sapi.gateway.mtls.HeaderCertificateRetriever;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilter.ParEndpointTransportCertValidationFilterHeaplet;
import com.forgerock.sapi.gateway.mtls.ResponsePathTransportCertValidationFilter.TokenEndpointTransportCertValidationFilterHeaplet;
import com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter;

public class SecureApiGatewayClassAliasResolver implements ClassAliasResolver {
    private static final Map<String, Class<?>> ALIASES = new HashMap<>();

    static {
        ALIASES.put("FapiAdvancedDCRValidationFilter", FapiAdvancedDCRValidationFilter.class);
        ALIASES.put("RsaJwtSignatureValidator", RsaJwtSignatureValidator.class);
        ALIASES.put("FetchApiClientFilter", FetchApiClientFilter.class);
        ALIASES.put("TransportCertValidationFilter", TransportCertValidationFilter.class);
        ALIASES.put("DefaultTransportCertValidator", DefaultTransportCertValidator.class);
        ALIASES.put("RegistrationRequestBuilderFilter", RegistrationRequestBuilderFilter.class);
        ALIASES.put("ConsentRequestAccessAuthorisationFilter", ConsentRequestAccessAuthorisationFilter.class);
        ALIASES.put("TokenEndpointTransportCertValidationFilter", TokenEndpointTransportCertValidationFilterHeaplet.class);
        ALIASES.put("ParEndpointTransportCertValidationFilter", ParEndpointTransportCertValidationFilterHeaplet.class);
        ALIASES.put("SapiLogAttachedExceptionFilter", SapiLogAttachedExceptionFilterHeaplet.class);
        ALIASES.put("CompactSerializationJwsSigner", CompactSerializationJwsSigner.class);
        ALIASES.put("AddCertificateToAttributesContextFilter", AddCertificateToAttributesContextFilter.class);
        ALIASES.put("ContextCertificateRetriever", ContextCertificateRetriever.class);
        ALIASES.put("HeaderCertificateRetriever", HeaderCertificateRetriever.class);
        ALIASES.put("RouteMetricsFilter", RouteMetricsFilter.class);
        ALIASES.put("AuthorizeResponseFetchApiClientFilter", AuthorizeResponseFetchApiClientFilterHeaplet.class);
        ALIASES.put("TokenEndpointMetricsContextSupplier", TokenEndpointMetricsContextSupplier.class);
        ALIASES.put("FapiAuthorizeRequestValidationFilter", FapiAuthorizeRequestValidationFilter.class);
        ALIASES.put("FapiParRequestValidationFilter", FapiParRequestValidationFilter.class);
        ALIASES.put("ParResponseFetchApiClientFilter", ParResponseFetchApiClientFilterHeaplet.class);
        ALIASES.put("JwtReSigner", JwtReSigner.class);
        ALIASES.put("AccessTokenResponseIdTokenReSignFilter", AccessTokenResponseIdTokenReSignFilter.class);
        ALIASES.put("AuthorizeResponseJwtReSignFilter", AuthorizeResponseJwtReSignFilter.class);
        ALIASES.put("FapiInteractionIdTracingFilter", FapiInteractionIdTracingFilter.class);
        ALIASES.put("ManageApiClientFilter", ManageApiClientFilter.class);
        ALIASES.put("PathParamClientIdRequestParameterLocator", PathParamClientIdRequestParameterLocator.class);
        ALIASES.put("QueryParamClientIdRequestParameterLocator", QueryParamClientIdRequestParameterLocator.class);
        ALIASES.put("TokenEndpointResponseFetchApiClientFilter", TokenEndpointResponseFetchApiClientFilter.class);
    }

    /**
     * Get the class for a short name alias.
     *
     * @param alias Short name alias.
     * @return      The class, or null if the alias is not defined.
     */
    @Override
    public Class<?> resolve(final String alias) {
        return ALIASES.get(alias);
    }
}
