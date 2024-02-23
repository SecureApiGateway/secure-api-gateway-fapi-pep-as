# secure-api-gateway-ig-extensions
This is an extension module for IG, it contains Filters and helper classes which can be called from Filters to handle
common tasks which are required to build a secure API gateway.

To install this module the jar needs to be placed into [config/7.2.0/securebanking/ig/lib](../config/7.2.0/securebanking/ig/lib).

Further documentation can be found on the wiki:
https://github.com/SecureApiGateway/SecureApiGateway/wiki/IG-Extensions-Java-Module

# Technical Documentation
## JWKS Caching Support
Support for fetching (and optionally caching) JSON Web Key Set (JWKS) data.

## Key classes
The JwkSetService interface is used to control the behaviour when fetching JWKS, the default implementation: [RestJwkSetService](src/main/java/com/forgerock/sapi/gateway/jwks/RestJwkSetService.java) will always fetch data using a HTTP call to a REST API.

The [CachingJwkSetService](src/main/java/com/forgerock/sapi/gateway/jwks/cache/CachingJwkSetService.java) provides caching support via a pluggable Cache interface. The service will first check its cache and return the cached JWKS if there is one, otherwise it will delegate to the RestJwkSetService to get the data and cache it.

[CaffeineCachingJwkSetService](src/main/java/com/forgerock/sapi/gateway/jwks/cache/caffeine/CaffeineCachingJwkSetService.java) provides a concrete implementation which uses the [caffeine](https://github.com/ben-manes/caffeine) library (this lib is already used within IG).

## Extensions
Clients can use an alternative caching library by writing an adaptor class which implements the [com.forgerock.sapi.gateway.jwks.cache.Cache](src/main/java/com/forgerock/sapi/gateway/jwks/cache/Cache.java) interface. 

The contents of package [com.forgerock.sapi.gateway.jwks.cache.caffeine](src/main/java/com/forgerock/sapi/gateway/jwks/cache/caffeine/) demonstrate how this can be done. In this package there is: a CaffeineCache adaptor class, CaffeineCachingJwkSetService (which extends CachingJwkSetService) and a heaplet object which is used to construct and configure the caffeine caching. 
